import os
import msgpack
from aiowmi.query import Query
from collections import Counter
from datetime import datetime, timedelta
from libprobe.asset import Asset
from ..wmiquery import wmiconn, wmiquery, wmiclose
from ..events import EVENTS, SECUTIRY


EVENTLOG_LAST_RUN_FN = os.getenv(
    'EVENTLOG_LAST_RUN_FN', '/data/eventlog_last_run.mp')
if not os.path.exists(EVENTLOG_LAST_RUN_FN):
    with open(EVENTLOG_LAST_RUN_FN, 'wb') as fp:
        msgpack.pack({}, fp)
with open(EVENTLOG_LAST_RUN_FN, 'rb') as fp:
    last_run_times = msgpack.unpack(fp, strict_map_key=False)

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
    custom = set(check_config.get('eventCodes', []))
    include_security = check_config.get('securityEvents', True)
    event_code, security = [], []
    if include_security:
        sec_ec = set(SECUTIRY)
        state = {'eventCode': event_code, 'security': security}
    else:
        sec_ec = set()
        state = {'eventCode': event_code}

    complete = tuple(custom) + tuple(sec_ec)
    if not complete:
        return state

    # By shifting the time window by one minute to the past, we allow the
    # target machine a little time drift from the probe and prevent missing
    # events written at the same second as we query.
    end = datetime.utcnow() - timedelta(seconds=60)
    if asset.id in last_run_times:
        last_end = last_run_times[asset.id]
        start = datetime.utcfromtimestamp(last_end)
    else:
        start = end - timedelta(seconds=60)

    query = Query(f"""
        SELECT
        EventCode, EventType, Logfile, Message, SourceName, TimeGenerated
        FROM Win32_NTLogEvent
        WHERE TimeWritten > "{start.strftime('%Y%m%d%H%M%S.000000-000')}" AND
        TimeWritten <= "{end.strftime('%Y%m%d%H%M%S.000000-000')}" AND
        ({' OR '.join(f'EventCode = {ec}' for ec in complete)})
    """)
    conn, service = await wmiconn(asset, asset_config, check_config)
    try:
        rows = await wmiquery(conn, service, query)
    finally:
        wmiclose(conn, service)

    # success, update and write last_run_times
    last_run_times[asset.id] = int(end.timestamp())
    with open(EVENTLOG_LAST_RUN_FN, 'wb') as fp:
        msgpack.pack(last_run_times, fp)

    ct = Counter()
    last = {}
    for row in sorted(rows, key=lambda row: row['TimeGenerated']):
        ct[row['EventCode']] += 1
        last[row['EventCode']] = row

    for ec in complete:
        item = {
            'name': str(ec),
            'Count': ct[ec],
            'Description': EVENTS.get(ec),
        }
        if ec in last:
            item['LastEventType'] = EVENT_TYPE.get(last[ec]['EventType'])
            item['LastLogfile'] = last[ec]['Logfile']
            item['LastMessage'] = msg = last[ec]['Message']
            item['LastSourceName'] = last[ec]['SourceName']
            item['LastTimeGenerated'] = int(last[ec]['TimeGenerated'])
            # Overwrite description
            item['Description'] = msg.split('\n', 1)[0]

        if ec in custom:
            event_code.append(item)
        if ec in sec_ec:
            security.append(item)

    return state
