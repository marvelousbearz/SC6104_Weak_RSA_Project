from bleichenbacher_attack import BleichenbacherAttack
from vunerable_server import VunerableServer

message = "This is a demo message."
message = message.encode("utf-8")
key_size = 1024

server = VunerableServer(key_size, message)

attacker = BleichenbacherAttack(server, attack_type="PKCS1_v1_5")

recovered_message = attacker.attack()

print("Message:", message)
print("Recovered Message:", recovered_message)
print("Iterations:", attacker.iterations)
print("Oracle calls:", server.get_query_count())
print("Search calls:", attacker._search_calls)