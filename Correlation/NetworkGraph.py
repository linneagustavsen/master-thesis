import json
import networkx as nx
import matplotlib.pyplot as plt

class NetworkGraph():
    def __init__(self):
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