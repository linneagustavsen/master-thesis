import stmpy
import paho.mqtt.client as mqtt
import networkx as nx
from threading import Thread
import json
import random
from datetime import datetime, timedelta
from datetime import date

#Parameters for the MQTT connection
MQTT_BROKER = 'mosquitto'
MQTT_PORT = 1883
MQTT_USER = 'aggregation'
MQTT_PASSWORD = 'aggregationPass'
MQTT_TOPIC = 'detections/modules/#'
MQTT_TOPIC_OUTPUT = 'detections/correlation'

class Aggregation:
    """
        The class is initialized with data fields and database dictionaries.
    """
    def __init__(self, broker, port, driver, inputTopic, outputTopic):
        self.driver = driver
        self.port = port
        self.broker = broker
        self.input = inputTopic
        self.output = outputTopic

        self.G = nx.Graph()
        self.G.add_nodes_from(["bergen-gw3", "bergen-gw4", "hoytek-gw2", "hovedbygget-gw", "trd-gw", "teknobyen-gw2", "teknobyen-gw1", "ifi2-gw5", "ifi2-gw", 
                    "oslo-gw1", "tromso-gw5", "stangnes-gw", "rodbergvn-gw2", "narvik-kv-gw", "narvik-gw3", "tromso-fh-gw",
                    "ma2-gw", "narvik-gw4", "tullin-gw2", "tullin-gw1"])
        self.G.add_edges_from([("trd-gw", "rodbergvn-gw2"),("narvik-kv-gw","trd-gw"), ("trd-gw", "teknobyen-gw2"), ("trd-gw", "oslo-gw1"), ("trd-gw", "hovedbygget-gw"),
                    ("teknobyen-gw2", "teknobyen-gw1"), ("teknobyen-gw2","ifi2-gw5"), ("narvik-kv-gw", "teknobyen-gw2"), ("narvik-kv-gw", "ifi2-gw5"), ("narvik-kv-gw", "stangnes-gw"),
                    ("narvik-kv-gw", "tromso-fh-gw"), ("narvik-kv-gw", "narvik-gw3"), ("narvik-kv-gw", "narvik-gw4"), ("tromso-fh-gw",  "ma2-gw"), ("tromso-fh-gw", "tromso-gw5"),
                    ("ma2-gw", "tromso-gw5"), ("ma2-gw","narvik-gw3"), ("ma2-gw", "narvik-gw4"), ("narvik-gw3", "narvik-gw4"), ("narvik-gw3", "hovedbygget-gw"), 
                    ("hovedbygget-gw", "tullin-gw2"), ("hovedbygget-gw", "hoytek-gw2"),("ifi2-gw5", "oslo-gw1"), ("ifi2-gw5", "ifi2-gw"), ("ifi2-gw", "bergen-gw4"),
                    ("ifi2-gw", "tullin-gw1"), ("ifi2-gw", "oslo-gw1"), ("oslo-gw1", "tullin-gw1"), ("tullin-gw1", "tullin-gw2"), ("tullin-gw2", "hoytek-gw2"),
                    ("tullin-gw1", "bergen-gw3"), ("rodbergvn-gw2", "stangnes-gw"), ("bergen-gw3", "bergen-gw4"), ("bergen-gw3", "hoytek-gw2"), ("narvik-kv-gw", "ifi2-gw"),
                    ("oslo-gw1", "narvik-kv-gw")])
        
        for node in self.G:
            self.G.nodes[node]['alerts'] = {}

    def on_connect(self, client, userdata, flags, rc):
        print("Connected with result code "+str(rc))
        self.mqtt_client.subscribe(self.input)

    """
        The MQTT commands are listened to and appropriate actions are taken for each.
    """
    #Function that is called when the sensor publish something to a MQTT topic
    def on_publish(client, userdata, result):
        print("Aggregation published to topic", MQTT_TOPIC)
    
    def on_message(self, client, userdata, msg):
        print('Incoming message to topic {}'.format(msg.topic))
        try:
            payload = json.loads(msg.payload.decode("utf-8"))
            print(payload)
        except Exception as err:
            print('Message sent to topic {} had no valid JSON. Message ignored. {}'.format(msg.topic, err))
            return

        stime = payload.get('sTime')
        etime = payload.get('eTime')
        fuzzyStartTime = stime - timedelta(seconds = 30)
        gateway = payload.get('Gateway')
        attack_type = payload.get('Attack_type')
        exists = False
        existTime = datetime()
        for i in range(int((etime-fuzzyStartTime).total_seconds())+1):
            time = fuzzyStartTime + timedelta(seconds = i)
            if time.replace(microsecond=0) in self.G.nodes[gateway]['alerts']:
                exists = True
                existTime = time
        
        if exists:
            self.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)].append(payload)
            if len(self.G.nodes[gateway]['alerts'][existTime.replace(microsecond=0)]) > 3:
                #self.mqtt_client.publish(self.output,json.dumps(G))
                self.driver.send('manyAlerts','Correlation', args=[self.G, gateway,])
        else:
            self.alertDB[gateway][etime.replace(microsecond=0)] = [payload]

    def start(self):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.on_connect = self.on_connect
        
        self.mqtt_client.connect(self.broker, self.port)
        try:
            thread = Thread(target=self.mqtt_client.loop_forever)
            thread.start()
        except KeyboardInterrupt:
            print("Interrupted")
            self.mqtt_client.disconnect()

"""
    This class is for correlating alerts from the aggregation.
"""
class Correlation:
    def __init__(self, aggregation):
        self.aggregation = aggregation

    def sendMessage(self, attackType, deviation_score, srcIP, dstIP, gateways):
        self.aggregation.mqtt_client.publish(MQTT_TOPIC_OUTPUT, json.dumps({"Attack_type": attackType, "Deviation_score": deviation_score, "srcIP": srcIP, "dstIP": dstIP, "Gateways": gateways}))
    
    def validateRegistration(self, username, name, password, walkieId, role, localServer):
        usernameInUse = False
        validServer = False
        validWalkie = False
        error = 0
        for x in self.authMqtt.registeredUsers.keys():
            if username == x:
                usernameInUse = True
                error = 7

        for x in self.authMqtt.localServerInfo.keys():
            if x == localServer:
                validServer = True

        for x in self.authMqtt.registeredWalkies.keys():
            if x == walkieId:
                validWalkie = True


        if usernameInUse:
            self.authMqtt.driver.send('notValidReg', 'Authentication_server', args=[error,walkieId])
        elif not validServer:
            error = 13
            self.authMqtt.driver.send('notValidReg', 'Authentication_server', args=[error,walkieId])
        elif not validWalkie:
            error = 14
            self.authMqtt.driver.send('notValidReg', 'Authentication_server', args=[error,walkieId])
        else:
            self.authMqtt.driver.send('validReg', 'Authentication_server', args=[username, name, password, walkieId, role, localServer])

    """
        Adds the user that wants to register to the "database"
    """       
    def registration(self, username, name, password, walkieId, role, localServer):
        self.authMqtt.registeredUsers.update({username: [name, password,localServer]})

    """
        Validates if the user can log in or not by checking if the username and password given matches a user in the database.
        Also checks if the walkieId given belongs to a valid walkie.
        If the user is valid to log in a message is sent to the driver with the username, password, walkieId, localServer and token.
        If a user is not valid the driver is notified and the incident is logged.
        Token is a unique string of hexadecimal numbers used for message authentication.
    """ 
    def validateLogin(self, username, password, walkieId, localServer):
        sentValid = False
        validWalkie = False
        token = ""
        error = None
        
        for i in range(32):
            del i
            randomNr = random.randint(0, 1)
            if randomNr == 0:
                randomUpperLetter = chr(random.randint(ord('A'), ord('F')))
                token += randomUpperLetter
            elif randomNr == 1:
                number = str(random.randint(1, 9))
                token += number

        for x in self.authMqtt.registeredWalkies.keys():
            if x == walkieId:
                validWalkie = True

        for x, y in self.authMqtt.registeredUsers.items():
            if x == username and y[1] == password and y[2]== localServer and validWalkie:
                self.authMqtt.driver.send('validLog', 'Authentication_server', args=[username, password, walkieId, token, localServer])
                sentValid = True
            else:
                error = 1

            
        if not sentValid:
            f = open("UnsuccessfulLoginsLog.txt", "a")
            now = datetime.now()
            current_time = now.strftime("%H:%M:%S")
            today = date.today()
            dateToday = today.strftime("%B %d, %Y")
            txt = "Date: {}. Time: {}. \nUser with username {} tried to login using {} as password with walkieId {}. This returned the error message {}.\n \n"
            f.write(txt.format(dateToday, current_time, username,password, walkieId, error))
            f.close()
            self.authMqtt.driver.send('notValidLog', 'Authentication_server', args = [error, walkieId])
            
    """
        Updates the database of registered walkie talkies to contain the current user field of the user logged in.
    """ 
    def login(self, username, password, walkieId, token, localServer):
        self.authMqtt.registeredWalkies[walkieId][2] = username

t0 = {
    'source': 'initial',
    'target': 'idle'}

t1 = {
    'trigger': 'loginRequest',
    'source': 'idle',
    'target': 'validating_login',
    'effect': 'validateLogin(*)'} # Variables are passed to the state machines with the (*) notation.

t2 = {
    'trigger': 'notValidLog',
    'source': 'validating_login',
    'effect': 'sendErrorLogin(*)',
    'target': 'idle'}

t3 = {
    'trigger': 'validLog',
    'source': 'validating_login',
    'target': 'idle',
    'effect': 'sendMessageLogin(*); login(*)'}

t4 = {
    'trigger': 'registrationRequest',
    'source': 'idle',
    'target': 'validating_registration',
    'effect': 'validateRegistration(*)'}

t5 = {
    'trigger': 'notValidReg',
    'source': 'validating_registration',
    'effect': 'sendErrorRegistration(*)',
    'target': 'idle'}

t6 = {
    'trigger': 'validReg',
    'source': 'validating_registration',
    'target': 'idle',
    'effect': 'registration(*); sendMessageReg(*)'}

idle = {'name': 'idle'}

validating_login = {
    'name': 'validating_login',
    'defer': 'registationRequest; loginRequest; delete_user; log_out'
}

validating_registration = {
    'name': 'validation_registration',
    'defer': 'registationRequest; loginRequest; delete_user; log_out'
}

driver = stmpy.Driver()
server = AuthenticationServer_MQTT(MQTT_BROKER, MQTT_PORT, driver, MQTT_TOPIC_INPUT, MQTT_TOPIC_OUTPUT)

authenticationSender = AuthenticationServer_Sender(server)
machine = stmpy.Machine(name='Authentication_server', transitions=[t0, t1, t2, t3, t4, t5, t6],
                        obj=authenticationSender, states=[idle, validating_login, validating_registration])
authenticationSender.stm = machine


driver.add_machine(machine)
server.start()
driver.start()