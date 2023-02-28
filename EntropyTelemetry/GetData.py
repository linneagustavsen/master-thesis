from influxdb_client import InfluxDBClient
'''
start: datetime
stop: datetime
systemId: string
if_name: string
fields: array of strings
'''

def getData(start, stop, systemId, if_name, fields):
    client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

    query_api = client.query_api()
    columns = ["_time"]

    query = 'from(bucket: "skogul/1mnd")\
                |> range(start: ' + start + ', stop: ' + stop + ')\
                |> filter(fn: (r) => r["systemId"] == "' + systemId + '")\
                |> filter(fn: (r) => r["if_name"] == "' + if_name + '")\
                |> filter(fn: (r) => '
    for i in range(len(fields)):
        query += 'r["_field"] == "' + fields[i] + '"'
        columns.append(fields[i])
        if len(fields) != 1 and i != len(fields)-1:
            query += ' or '
        
    query += ')\
    |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")\
    |> keep(columns: ' + str(columns).replace("'", '"') + ')'

    #Make a data frame from the output of the query
    df = query_api.query_data_frame(query=query)

    if not df.empty:
        df = df.drop(columns=['result', 'table'])

    return df
