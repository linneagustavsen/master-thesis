from influxdb_client import InfluxDBClient
import pandas as pd
'''
start: datetime
stop: datetime
systemId: string
if_name: string
field: string
'''

def getData(start, stop, systemId, if_name, field):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()

    query = 'from(bucket: "skogul/1mnd")\
            |> range(start: ' + start + ', stop: ' + stop + ')\
            |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
            |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
            |> filter(fn: (r) => r["_field"] == "' + field + '")\
            |> group()        \
            |> keep(columns: ["_value", "_time"])'

    #Make a flux table list from the output of the query
    df = query_api.query_data_frame(query=query)
    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df