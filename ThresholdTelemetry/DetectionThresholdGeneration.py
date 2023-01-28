from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json

json_file = open("/home/linneafg/Code/master-thesis/ThresholdTelemetry/RawValuesSchema.json", "r")
json_object = json.load(json_file)
json_file.close()

client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7", timeout=100000)

query_api = client.query_api()

for weekday in range(1):
    for hour in range(1):
        for minute in range(60):
            query = 'import "date" from(bucket: "skogul/1mnd")\
                    |> range(start: 2022-09-21T02:00:00Z, stop: 2022-10-21T12:40:00Z)\
                    |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
                    |> filter(fn: (r) => r["sensorName"] == "interface:/junos/system/linecard/interface/:/junos/system/linecard/interface/:PFE")\
                    |> filter(fn: (r) => r["_measurement"] == "junos_system_linecard_interface")\
                    |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
                    |> filter(fn: (r) => date.weekDay(t: r._time)==' +str(weekday)+' and date.hour(t: r._time)==' +str(hour)+' and date.minute(t: r._time)==' +str(minute)+')\
                    |> keep(columns: ["_value", "_time"])'
            tables = query_api.query(query=query)
            for table in tables:
                for row in table.records:
                    json_object["weekday"][str(weekday)]["hour"][str(hour)]["minute"][str(minute)].append(row.values["_value"])
json_file = open("RawValues.json", "w")
json.dump(json_object,json_file)
json_file.close()
