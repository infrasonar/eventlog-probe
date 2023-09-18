from aiowmi.query import Query
from collections import Counter, defaultdict
from libprobe.asset import Asset
from ..wmiquery import wmiconn, wmiquery, wmiclose


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

    query = Query(f"""
        SELECT
        EventCode, EventType, Logfile, Message, SourceName, TimeGenerated
        FROM Win32_NTLogEvent
        WHERE {' OR '.join(f'EventCode = {ec}' for ec in ec)}
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
