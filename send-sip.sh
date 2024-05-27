#!/bin/bash

DEST_IP=$1
DEST_PORT=$2
LONG_SHORT=$3

SIP_INVITE_SHORT='Dec 30 01:01:01.111 On [0:0]192.168.123.123:5060 sent to 192.168.123.124:5060
INVITE sip:123@192.168.123.124:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Contact: "Example"<sip:example@192.168.123.123:5060;transport=udp>
Supported: 100rel
From: "Example"<sip:example@example.invalid>;tag=aaaaaaaaaaaaaaaaaaaa
To: <sip:123@192.168.123.124:5060>
Call-ID: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
CSeq: 2 INVITE
P-Preferred-Identity: "iden"<sip:11111@192.168.123.123:5060>
<b>Privacy: id<\b>
Content-Length: 200
Content-Type: application/sdp
Max-Forwards: 80
v=0
o=IWF 5 5 IN IP4 192.168.123.125
s=H323 Call
c=IN IP4 192.168.123.124
t=0 0
m=audio 5010 RTP/AVP 0
a=rtpmap:0 PCMU/8000/1
m=video 5014 RTP/AVP 31
a=rtpmap:31 H261/9000/1'

SIP_INVITE_LONG='Dec 30 01:01:01.111 On [0:0]192.168.123.123:5060 sent to 192.168.123.124:5060
INVITE sip:123@192.168.123.124:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Via: SIP/2.0/UDP 192.168.123.123:5060;branch=aaaaaaaaaaaaaaaaaaaaaaaaaaaa.2
Contact: "Example"<sip:example@192.168.123.123:5060;transport=udp>
Supported: 100rel
From: "Example"<sip:example@example.invalid>;tag=aaaaaaaaaaaaaaaaaaaa
To: <sip:123@192.168.123.124:5060>
Call-ID: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
CSeq: 2 INVITE
P-Preferred-Identity: "iden"<sip:11111@192.168.123.123:5060>
<b>Privacy: id<\b>
Content-Length: 200
Content-Type: application/sdp
Max-Forwards: 80
v=0
o=IWF 5 5 IN IP4 192.168.123.125
s=H323 Call
c=IN IP4 192.168.123.124
t=0 0
m=audio 5010 RTP/AVP 0
a=rtpmap:0 PCMU/8000/1
m=video 5014 RTP/AVP 31
a=rtpmap:31 H261/9000/1'

if [ "$LONG_SHORT" == "long" ]; then
  echo "$SIP_INVITE_LONG" | nc $DEST_IP $DEST_PORT 
  exit
fi
echo "$SIP_INVITE_SHORT" | nc $DEST_IP $DEST_PORT 
