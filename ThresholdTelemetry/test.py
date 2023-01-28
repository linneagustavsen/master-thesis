from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS


client = InfluxDBClient(url="http://localhost:8086", token="XIXjEYH2EUd8fewS0niwHcdif20ytyhNR3dqPYppD0S8LQeA7CnICVVnlke6H3kmN0cvTVoINmXqz1aCbCxL6A==", org="4bad65ca5da036f7")

query_api = client.query_api()

query = 'from(bucket: "skogul/1mnd")\
    |> range(start: 2022-09-22T02:00:00Z, stop: 2022-09-22T02:01:00Z)\
    |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
    |> filter(fn: (r) => r["sensorName"] == "interface:/junos/system/linecard/interface/:/junos/system/linecard/interface/:PFE")\
    |> filter(fn: (r) => r["_measurement"] == "junos_system_linecard_interface")\
    |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
    |> drop(columns: ["_start", "_stop", "_field", "_measurement", "location", "componentId", "descr","if_name", "link_name", "measurement", "sensorName", "sn_int", "subComponentId", "systemId", "sn_ext"])'



#for i in range(6):
'''query = 'import "date" from(bucket: "skogul/1mnd")\
        |> range(start: 2022-09-21T02:00:00Z, stop: 2022-10-21T12:40:00Z)\
        |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
        |> filter(fn: (r) => r["sensorName"] == "interface:/junos/system/linecard/interface/:/junos/system/linecard/interface/:PFE")\
        |> filter(fn: (r) => r["_measurement"] == "junos_system_linecard_interface")\
        |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
        |> filter(fn: (r) => date.weekDay(t: r._time)==2 )\
        |> map(fn: (r) => ({r with hour: \
            if date.hour(t: r._time) > 9 then string(v: date.hour(t: r._time)) \
            else "0" + string(v: date.hour(t: r._time)),minute: \
            if date.minute(t: r._time) > 9 then string(v: date.minute(t: r._time)) \
            else "0" + string(v: date.minute(t: r._time)), second: \
            if date.second(t: r._time) > 9 then string(v: date.second(t: r._time)) \
            else "0" + string(v: date.second(t: r._time)) }))\
        |> map(fn: (r) => ({r with _time: time(v: "2000-01-01T" + r.hour+ ":" +r.minute+ ":"+ r.second + "Z")}))\
        |> keep(columns: ["_time", "_value"])'
        '''

'''
for weekday in range(6):
    for hour in range(24):
        for minute in range(60):
            query = 'import "date" from(bucket: "skogul/1mnd")\
                    |> range(start: 2022-09-21T02:00:00Z, stop: 2022-10-21T12:40:00Z)\
                    |> filter(fn: (r) => r["link_name"] == "alta-narvik")\
                    |> filter(fn: (r) => r["sensorName"] == "interface:/junos/system/linecard/interface/:/junos/system/linecard/interface/:PFE")\
                    |> filter(fn: (r) => r["_measurement"] == "junos_system_linecard_interface")\
                    |> filter(fn: (r) => r["_field"] == "egress_stats__if_1sec_pkts")\
                    |> filter(fn: (r) => date.weekDay(t: r._time)==' +str(weekday)+' and date.hour(t: r._time)==' +str(hour)+' and date.minute(t: r._time)==' +str(minute)+')\
                    |> keep(columns: ["_value"])'
'''

## using Table structure
tables = query_api.query(query=query)

for table in tables:
    print(table)
    for row in table.records:
        print (row.values['_time'].weekday())
