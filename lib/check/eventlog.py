import os
import msgpack
from aiowmi.query import Query
from collections import Counter
from datetime import datetime, timedelta
from libprobe.asset import Asset
from ..wmiquery import wmiconn, wmiquery, wmiclose


EVENTLOG_LAST_RUN_FN = os.getenv(
    'EVENTLOG_LAST_RUN_FN', '/data/eventlog_last_run.mp')
if not os.path.exists(EVENTLOG_LAST_RUN_FN):
    with open(EVENTLOG_LAST_RUN_FN, 'wb') as fp:
        msgpack.pack({}, fp)
TYPE_NAME = 'eventCode'

EVENT_TYPE = {
    1: 'Error',
    2: 'Warning',
    3: 'Information',
    4: 'Security Audit Success',
    5: 'Security Audit Failure',
}


async def check_eventlog(
        asset: Asset,
        asset_config: dict,
        check_config: dict) -> dict:
    ec = check_config.get('eventCodes')
    if not ec:
        return {
            TYPE_NAME: []
        }

    now = datetime.now()
    with open(EVENTLOG_LAST_RUN_FN, 'rb') as fp:
        last_run_times = msgpack.unpack(fp, strict_map_key=False)
    if asset.id in last_run_times:
        last_run_time = last_run_times[asset.id]
        after = datetime.utcfromtimestamp(last_run_time)
    else:
        after = now - timedelta(seconds=60)

    last_run_times[asset.id] = int(now.timestamp())
    with open(EVENTLOG_LAST_RUN_FN, 'wb') as fp:
        msgpack.pack(last_run_times, fp)

    query = Query(f"""
        SELECT
        EventCode, EventType, Logfile, Message, SourceName, TimeGenerated
        FROM Win32_NTLogEvent
        WHERE {' OR '.join(f'EventCode = {ec}' for ec in ec)} AND
        TimeWritten > "{after.strftime('%Y%m%d%H%M%S.000000-000')}"
    """)
    conn, service = await wmiconn(asset, asset_config, check_config)
    try:
        rows = await wmiquery(conn, service, query)
    finally:
        wmiclose(conn, service)

    ct = Counter()
    last = {}
    for row in sorted(rows, key=lambda row: row['TimeGenerated']):
        ct[row['EventCode']] += 1
        last[row['EventCode']] = row

    items = []
    for ec in ec:
        item = {
            'name': str(ec),
            'Count': ct[ec],
        }
        if ec in last:
            item['LastEventType'] = EVENT_TYPE.get(last[ec]['EventType'])
            item['LastLogfile'] = last[ec]['Logfile']
            item['LastMessage'] = last[ec]['Message']
            item['LastSourceName'] = last[ec]['SourceName']
            item['LastTimeGenerated'] = int(last[ec]['TimeGenerated'])

        items.append(item)
    return {
        TYPE_NAME: [items]
    }
