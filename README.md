# Firewall
Illustrates the scenario of the working of a firewall system between a set of hosts using the rule sets that are fed to the system. Firstly we implement a simple firewall, which relies on the idea of pre-coded/hot coded rules using conditional statements. Then we try to implement a more advanced and sophisticated system that works on the dynamic set of rules and defines a complete firewall system that provides rule management (CRUD of Rule sets), Command line interface for user interaction. We then also benchmark the designed system across a set of parameters and determine the PPS (Packets Per Second) processing by the system by plotting a set of graphs. The system is further extended to employ the DoS attack detection mechanism.

# Network Configuration

![image](https://user-images.githubusercontent.com/55399754/118126305-c78ab000-b415-11eb-9151-c7f418ac96c1.png)

**Running Simple Firewall at layer 2 level**

In this task the firewall is designed at the layer 2 ethernet level that works filtering using the
MAC addresses. The simple firewall class in the “firewall.py” code implements this design and
system. This is executed as follows:

Command : python firewall.py simple_firewall <external_host_interface>
<internal_host_interface>

![image](https://user-images.githubusercontent.com/55399754/118126463-0456a700-b416-11eb-8047-b99767312ead.png)

We run the firewall, and from the internal interface send a packet using the nping command
“nping -e enp1s0 192.168.1.7”. This packet is captured by the firewall first and according to the
rule it is allowed as shown below.

![image](https://user-images.githubusercontent.com/55399754/118126554-1fc1b200-b416-11eb-9c04-b45e0e13dd72.png)

**Advanced Firewall System (Filtering at layer 2[Ether], 3 [IP] and 4
[TCP,UDP]):**

In this task we move ahead to design a more sophisticated system, that allows dynamic rule
management (ADD, UPDATE and DELETE) , CLI interface, Saving and loading of the rules.
The advanced firewall mode is executed in the “firewall.py” code as follows.

Command : python firewall.py adv_firewall <external_host_interface>
<internal_host_interface>

![image](https://user-images.githubusercontent.com/55399754/118126633-3d8f1700-b416-11eb-8b4d-45e215c546e0.png)

![image](https://user-images.githubusercontent.com/55399754/118126694-50095080-b416-11eb-94d1-7b85962464e8.png)

![image](https://user-images.githubusercontent.com/55399754/118126737-5b5c7c00-b416-11eb-84a7-f11c75eeacfc.png)

![image](https://user-images.githubusercontent.com/55399754/118126793-70d1a600-b416-11eb-9a38-8ec5c4049ca9.png)

![image](https://user-images.githubusercontent.com/55399754/118126816-7a5b0e00-b416-11eb-8212-b5f12c1a1554.png)

![image](https://user-images.githubusercontent.com/55399754/118126840-834bdf80-b416-11eb-9921-71a8656bdf71.png)

![image](https://user-images.githubusercontent.com/55399754/118126884-8e9f0b00-b416-11eb-8bcf-ca38afc9265c.png)

![image](https://user-images.githubusercontent.com/55399754/118126926-9eb6ea80-b416-11eb-8a6c-3cdb27e109cb.png)

![image](https://user-images.githubusercontent.com/55399754/118126948-a6768f00-b416-11eb-88e1-deb6690361ee.png)

**ICMP Filtering/ ICMP rule emulation :**

Defining the ICMP rules in the system to check filtering against ICMP protocol packers. The
ICMP is identified from the IP packet using the protocol number ‘1’.

![image](https://user-images.githubusercontent.com/55399754/118127014-bb532280-b416-11eb-8b78-e48da3c74bd1.png)

![image](https://user-images.githubusercontent.com/55399754/118127039-c443f400-b416-11eb-8c68-9e3e656ef391.png)

**Discarding ICMP requests from external host:**

We define the following rule that doesn't allow the ICMP echo requests to the internal host.

![image](https://user-images.githubusercontent.com/55399754/118127094-db82e180-b416-11eb-8269-ca65862accdb.png)

# Benchmarking and performance analysis of advanced firewall
In this task, we try to benchmark the system with respect to the packet processing powers, packet
per second handling by the system, and also the performance of the system with respect to the
number of rules and matching fields in the system.
Tool used for benchmarking : nping from nmap repository to generate various packets.

![image](https://user-images.githubusercontent.com/55399754/118127143-f35a6580-b416-11eb-8b18-10da084bdd4c.png)

![image](https://user-images.githubusercontent.com/55399754/118127165-fe14fa80-b416-11eb-8754-478d21cda83e.png)

![image](https://user-images.githubusercontent.com/55399754/118127208-0705cc00-b417-11eb-9d72-48128fb628fb.png)

![image](https://user-images.githubusercontent.com/55399754/118127250-1127ca80-b417-11eb-9c1e-1000f203a420.png)

![image](https://user-images.githubusercontent.com/55399754/118127274-1ab13280-b417-11eb-9d8a-45f1515c4fbb.png)

![image](https://user-images.githubusercontent.com/55399754/118127300-23096d80-b417-11eb-9f2b-e8369c41c331.png)

![image](https://user-images.githubusercontent.com/55399754/118127340-2f8dc600-b417-11eb-81b8-159096fbe726.png)

![image](https://user-images.githubusercontent.com/55399754/118127403-47654a00-b417-11eb-8c98-868f9cf5b8cd.png)

![image](https://user-images.githubusercontent.com/55399754/118127433-51874880-b417-11eb-81b6-a1fa4c14aa78.png)

# Attack Detection (CHOSEN ATTACK : DoS)

In this task, the advanced firewall system is extended to detect certain attacks that exist in the
networking communication. We choose to employ the DoS attack detection in the firewall. We
first understand the DoS attack as follows:

![image](https://user-images.githubusercontent.com/55399754/118127485-649a1880-b417-11eb-907d-04e42d04ca86.png)

The following workflow shows the DoS detection by the system.

![image](https://user-images.githubusercontent.com/55399754/118127554-7bd90600-b417-11eb-8803-91b463ceeb7f.png)

![image](https://user-images.githubusercontent.com/55399754/118127576-84c9d780-b417-11eb-8d39-5e15d797111d.png)

# Technical Specifications:

![image](https://user-images.githubusercontent.com/55399754/118127649-9a3f0180-b417-11eb-918c-f57cc216945a.png)

![image](https://user-images.githubusercontent.com/55399754/118127695-a88d1d80-b417-11eb-8e53-3b1a869041c8.png)

![image](https://user-images.githubusercontent.com/55399754/118127735-b0e55880-b417-11eb-87ba-64d93107c051.png)

![image](https://user-images.githubusercontent.com/55399754/118127770-ba6ec080-b417-11eb-9e9d-47e63525be4c.png)

![image](https://user-images.githubusercontent.com/55399754/118127811-c490bf00-b417-11eb-8aa5-a938bb12ad3e.png)

![image](https://user-images.githubusercontent.com/55399754/118127841-cd819080-b417-11eb-840a-c3ca1a14e969.png)


