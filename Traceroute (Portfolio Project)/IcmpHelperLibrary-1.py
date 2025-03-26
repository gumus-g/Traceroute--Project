'''
References:
 1. https://www.rfc-editor.org/rfc/rfc792?form=MG0AV3
 2. https://github.com/cameron-mccawley/classwork/blob/2ea73b209f6712f1120886a89ee5b3778b2260d5/CS-372/Project3/IcmpHelperLibrary.py
 3. https://www.geeksforgeeks.org/traceroute-implementation-on-python/
 4. https://rednafi.com/python/implement_traceroute_in_python/
 5. https://www.google.com/search?q=Traceroute+Implementation+&sca_esv=1e68560f6949762e&rlz=1C1RXQR_enUS932US932&udm=7&biw=1377&bih=779&ei=9zPOZ8zxO6Oq0PEPrqPN4QE&ved=0ahUKEwiMyerDov6LAxUjFTQIHa5RMxwQ4dUDCBA&uact=5&oq=Traceroute+Implementation+&gs_lp=EhZnd3Mtd2l6LW1vZGVsZXNzLXZpZGVvIhpUcmFjZXJvdXRlIEltcGxlbWVudGF0aW9uIDIGEAAYFhgeMgsQABiABBiGAxiKBTILEAAYgAQYhgMYigUyBRAAGO8FMgUQABjvBTIIEAAYgAQYogRIqwdQlQVYlQVwAXgAkAEAmAFAoAFAqgEBMbgBA8gBAPgBAZgCAqACT5gDAIgGAZIHATKgB-kD&sclient=gws-wiz-modeless-video#fpstate=ive&vld=cid:2f4228ed,vid:HgYuBN0ZYu0,st:0
'''
# #################################################################################################################### #
# Imports                                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
import os
from socket import *
import struct
import time
import select


# #################################################################################################################### #
# Class IcmpHelperLibrary                                                                                              #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
class IcmpHelperLibrary:
    # ################################################################################################################ #
    # Class IcmpPacket                                                                                                 #
    #                                                                                                                  #
    # References:                                                                                                      #
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket:
        # ############################################################################################################ #
        # IcmpPacket Class Scope Variables                                                                             #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live
        
        rtt = []                        # Hold different rtt to calculate min, max, avg
        validPacketCount = []           # Keep track of how many packets received are valid
        __replyType = 11                # Hold ICMP Type Number in reply packet

        __DEBUG_IcmpPacket = False      # Allows for debug output

        # ############################################################################################################ #
        # IcmpPacket Class Getters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl
        
        def getreplyType(self):
            return self.__replyType

        # ############################################################################################################ #
        # IcmpPacket Class Setters                                                                                     #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

             # Resolve hostname to IP address if provided as a string
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        def setreplyType(self, replyType):
            self.__replyType = replyType

        # ############################################################################################################ #
        # IcmpPacket Class Private Functions                                                                           #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            
            # Extract the identifier from the sent and received packets
            sentID = self.getPacketIdentifier()
            replyID = icmpReplyPacket.getIcmpIdentifier()
            
            # Extract the sequence numbers from the sent and received packets
            sentSequenceNumber = self.getPacketSequenceNumber()
            replySequenceNumber = icmpReplyPacket.getIcmpSequenceNumber()
            
            # Extract the data payload from the sent and received packets
            sentData = self.getDataRaw()
            replyData = icmpReplyPacket.getIcmpData()
            
            # Extract the ICMP type from the reply packet
            replyType = icmpReplyPacket.getIcmpType()
            self.setreplyType(replyType)

            # Debugging: Print out expected vs actual values for validation purposes
            if self.__DEBUG_IcmpPacket:
                print('Expected: Identifier = %d, Sequence Number = %d, Data = %s' % (sentID, sentSequenceNumber, sentData))
                print('Actual:   Identifier = %d, Sequence Number = %d, Data = %s' % (replyID, replySequenceNumber, replyData))
            
            #  Assume the response is valid initially
            validResponse = True

            # Validate the identifier
            if replyID != sentID:
                validResponse = False
                icmpReplyPacket.setIcmpIdentifier_isValid(False)
                print(f"Identifier mismatch: Expected {sentID}, Got {replyID}") if self.__DEBUG_IcmpPacket else None
            else:
                icmpReplyPacket.setIcmpIdentifier_isValid(True)

            # Validate the sequence number
            if replySequenceNumber != sentSequenceNumber:
                validResponse = False
                icmpReplyPacket.setIcmpSequenceNumber_isValid(False)
                print(f"Sequence Number mismatch: Expected {sentSequenceNumber}, Got {replySequenceNumber}") if self.__DEBUG_IcmpPacket else None
            else:
                icmpReplyPacket.setIcmpSequenceNumber_isValid(True)

            # Validate the data payload
            if replyData != sentData:
                validResponse = False
                icmpReplyPacket.setIcmpData_isValid(False)
                print(f"Data mismatch: Expected {sentData}, Got {replyData}") if self.__DEBUG_IcmpPacket else None
            else:
                icmpReplyPacket.setIcmpData_isValid(True)

            # Set overall validity of response
            icmpReplyPacket.setIsValidResponse(validResponse)
         
        # ############################################################################################################ #
        # IcmpPacket Class Public Functions                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self, action):                
            # ICMP error messages         
            if action == 'ping':
                # Display target and destination information when running a ping
                print("Pinging (" + self.__icmpTarget + ") " + self.__destinationIpAddress)
            
            # Define common ICMP error messages with their respective Type and Code combinations
            icmpErrors = {
                (3, 0): "Destination Network Unreachable",
                (3, 1): "Host Unreachable",
                (3, 6): "Destination Network Unknown",
                (3, 7): "Destination Host Unknown",
                (11, 0): "Time to live exceeded in Transit"
            }

            # Create a raw socket for ICMP communication
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(self.__ipTimeout)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))

            try:
                # Send the ICMP echo request
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                pingStartTime = time.time()  # Start time for calculating RTT
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], self.__ipTimeout)
                endSelect = time.time()
                howLongInSelect = endSelect - startedSelect

                # Handle case where no response is received within the timeout
                if not whatReady[0]:
                    return {'ttl': self.getTtl(), 'rtt': None, 'type': None, 'code': None,
                            'description': "Request timed out", 'address': None}

                # Receive the packet
                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                rtt = round((timeReceived - pingStartTime) * 1000, 0)  # Calculate RTT

                # Extract ICMP Type and Code from the response packet
                icmpType, icmpCode = recvPacket[20], recvPacket[21]
                description = icmpErrors.get((icmpType, icmpCode), "Unknown ICMP Error")

                # Return structured information for this ICMP packet
                return {'ttl': self.getTtl(), 'rtt': rtt, 'type': icmpType, 'code': icmpCode,
                        'description': description, 'address': addr[0]}

            except timeout:
                # Handle socket timeout exceptions gracefully
                return {'ttl': self.getTtl(), 'rtt': None, 'type': None, 'code': None,
                        'description': "Request timed out (By Exception)", 'address': None}

            finally:
                # Ensure the socket is closed
                mySocket.close()       
            
        
        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # ################################################################################################################ #
    # Class IcmpPacket_EchoReply                                                                                       #
    #                                                                                                                  #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    class IcmpPacket_EchoReply:
        # ############################################################################################################ #
        # IcmpPacket_EchoReply Class Scope Variables                                                                   #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        __recvPacket = b''
        __isValidResponse = False
        IcmpIdentifier_isValid = False
        IcmpSequenceNumber_isValid = False
        IcmpData_isValid = False
        IcmpType_isValid = False
        IcmpCode_isValid = False
        IcmpHeaderChecksum_isValid = False
        rtt = []
        totalValid = []

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Constructors                                                                            #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Getters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse
        
        def getIcmpIdentifier_isValid(self):
            return self.IcmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.IcmpSequenceNumber_isValid
        
        def getIcmpData_isValid(self):
            return self.IcmpData_isValid

        def getIcmpType_isValid(self):
            return self.IcmpType_isValid
        
        def getIcmpCode_isValid(self):
            return self.IcmpCode_isValid

        def getIcmpHeaderChecksum_isValid(self):
            return self.IcmpHeaderChecksum_isValid

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Setters                                                                                 #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.IcmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.IcmpSequenceNumber_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.IcmpData_isValid = booleanValue

        def setIcmpType_isValid(self, booleanValue):
            self.IcmpType_isValid = booleanValue

        def setIcmpCode_isValid(self, booleanValue):
            self.IcmpCode_isValid = booleanValue

        def setIcmpHeaderChecksum_isValid(self, booleanValue):
            self.IcmpHeaderChecksum_isValid = booleanValue

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Private Functions                                                                       #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # ############################################################################################################ #
        # IcmpPacket_EchoReply Public Functions                                                                        #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        #                                                                                                              #
        # ############################################################################################################ #
        def printResultToConsole(self, ttl, timeReceived, addr, icmpType):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
           
            rtt = (timeReceived - timeSent) * 1000  # Calculate RTT

            # Determine type description based on ICMP type
            typeDescriptions = {
                0: "Echo Reply",
                3: "Destination Unreachable",
                11: "Time Exceeded"
            }
            typeDescription = typeDescriptions.get(icmpType, "Unknown ICMP Type")

            # Print results
            print(f"{typeDescription}: TTL={ttl} RTT={rtt:.0f} ms Type={self.getIcmpType()} Code={self.getIcmpCode()} Identifier={self.getIcmpIdentifier()} Sequence Number={self.getIcmpSequenceNumber()} {addr[0]}")

            # Check validity
            valid = (self.getIcmpIdentifier_isValid() and 
                    self.getIcmpSequenceNumber_isValid() and 
                    self.getIcmpData_isValid() and 
                    self.getIcmpCode_isValid() and 
                    self.getIcmpType_isValid())
            
            print('  Echo Response Valid = %s\n' % valid)

            if valid:
                self.totalValid.append(1)  # Count valid packet
            self.rtt.append(rtt)  # Store RTT for statistics
    # ################################################################################################################ #
    # Class IcmpHelperLibrary                                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #

    # ################################################################################################################ #
    # IcmpHelperLibrary Class Scope Variables                                                                          #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output

    # ################################################################################################################ #
    # IcmpHelperLibrary Private Functions                                                                              #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            icmpPacket.sendEchoRequest('ping')                                                # Build IP

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data

        # Calculate the packet loss percentage
        # Subtract the count of valid responses from the total sent (4 in this case),
        # then calculate the percentage of lost packets
        lossPackets = (4 - len(icmpPacket.validPacketCount)) / 4 * 100  # Calculate packet lossPackets percentage

        # Print statistics
        print(f'Ping statistics for {host}:')
        print(f'  Packets: Sent = 4, Received = {len(icmpPacket.validPacketCount)}, Lost = {4 - len(icmpPacket.validPacketCount)} ({lossPackets:.1f}% loss)')

        if len(icmpPacket.rtt) > 0:
            print('Approximate round trip times in milli-seconds:')
            print(f'  Minimum = {min(icmpPacket.rtt):.0f}ms, Maximum = {max(icmpPacket.rtt):.0f}ms, Average = {sum(icmpPacket.rtt) / len(icmpPacket.rtt):.0f}ms')
                    # ICMP error messages          

        
    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        # Build code for trace route here          
                
        maxHops = 30  # Maximum hops for traceroute
        ttl = 1

        print(f"Traceroute to {host} ({host})")
        while ttl <= maxHops:
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            icmpPacket.setTtl(ttl)  # Set TTL for the current hop
            randomIdentifier = os.getpid() & 0xffff
            packetIdentifier = randomIdentifier
            packetSequenceNumber = ttl

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build the ICMP packet
            icmpPacket.setIcmpTarget(host)

            # Send the packet and get the response
            response = icmpPacket.sendEchoRequest('trace')

            # Check the response and adjust the output
            if response['rtt'] is None:
                # If the response times out, print "* * *" style output
                print("*        *        *        *        *    Request timed out.")
            else:
                # Display detailed information for valid responses
                print(f"TTL={response['ttl']}    RTT={response['rtt']} ms    Type={response['type']}    Code={response['code']} ({response['description']})    {response['address']}")

            # Stop if we receive an Echo Reply (Type 0)
            if response['type'] == 0:
                print("Trace complete.")  # Notify user that traceroute is complete
                break

            # Increment TTL for the next hop
            ttl += 1

        print("Traceroute completed.")  # Final message to indicate the traceroute has finished

    # ################################################################################################################ #
    # IcmpHelperLibrary Public Functions                                                                               #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    #                                                                                                                  #
    # ################################################################################################################ #
    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
#                                                                                                                      #
# #################################################################################################################### #
def main():
    icmpHelperPing = IcmpHelperLibrary()


    # Choose one of the following by uncommenting out the line
    # icmpHelperPing.sendPing("209.233.126.254")
    # icmpHelperPing.sendPing("www.google.com")
    #icmpHelperPing.sendPing("gaia.cs.umass.edu")
    # icmpHelperPing.traceRoute("164.151.129.20")
    #icmpHelperPing.traceRoute("122.56.99.243") #New Zealand
    #icmpHelperPing.traceRoute("203.0.113.1")
    #icmpHelperPing.traceRoute("198.51.100.1") # Europe
    #icmpHelperPing.traceRoute("200.10.227.250") # South America
    #icmpHelperPing.traceRoute("200.10.227.248") # Brazil
    icmpHelperPing.traceRoute("110.10.227.203")
    

if __name__ == "__main__":
    main() 
