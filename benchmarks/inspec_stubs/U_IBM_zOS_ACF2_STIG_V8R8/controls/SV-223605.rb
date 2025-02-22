control 'SV-223605' do
  title 'IBM z/OS Started tasks for the Base TCP/IP component must be defined in accordance with security requirements.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "Verify Logonid(s) assigned to the TCP/IP address space(s), are named TCPIP or, in the case of multiple instances, are prefixed with TCPIP.

From an ACF Command screen enter:
SET LID
LIST LIKE(TCPIP-)

If each TCP/IP logonid its defined with STC, MUSASS, and NO-SMC attributes, this is not a finding.

From the ACF Command screen enter:
SET LID
LIST LIKE(TCPIP-) PROFILE(OMVS)

If the z/OS UNIX attributes are UID(0), HOME directory '/', shell program /bin/sh, this is not a finding.

From an ACF Command screen enter:
SET LID
LIST EZAZSSI

If THE EZAZSSI logonid is defined with STC attribute, this is not a finding.

From the ACF Command screen enter:
SET LID
LIST EZAZSSI PROFILE(OMVS)

If the z/OS UNIX attributes are UID(0), HOME directory '/', shell program /bin/sh, this is not a finding."
  desc 'fix', "Define the Started tasks for the Base TCP/IP component user accounts with the following characteristics:

Named TCPIP or, in the case of multiple instances, prefixed with TCPIP
Defined with the STC, MUSASS, and NO-SMC attributes
z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh

Named EZAZSSI
Defined with the STC attribute
z/OS UNIX attributes: UID(non-zero), HOME directory '/', shell program /bin/sh

Review the TCP/IP started task accounts, privileges, and access authorizations defined to the ACP. Ensure they conform to the requirements as outlined below.

The following commands can be used to create the user accounts that are required for the TCP/IP address space and the EZAZSSI started task:

SET LID
INSERT TCPIP NAME(TCPIP) GROUP(STCTCPX) STC MUSASS NO-SMC
INSERT EZAZSSI NAME(EZAZSSI) GROUP(STCTCPX) STC

SET PROFILE(USER) DIVISION(OMVS)
INSERT TCPIP UID(0) HOME(/) OMVSPGM(/bin/sh)
INSERT EZAZSSI UID(non-zero) HOME(/) OMVSPGM(/bin/sh)

F ACF2,REBUILD(USR),CLASS(P)

NOTE: At eTrust CA-ACF2 6.4 and above, the PROGRAM field in the user profile record has been renamed to OMVSPGM.

The following additions to the indicated rule sets can be used to assign the privileges that are required for the TCP/IP address space:

$KEY(BPX) TYPE(FAC)
...
DAEMON UID(TCPIP-uid) SERVICE(READ) ALLOW

If the z/OS host machine has hardware encryption installed and enabled, resources owned by the Integrated Cryptographic Service Facility (ICSF) component have been defined. The following rule set additions are required to allow the TN3270 Telnet Server process to access the ICSF resources. 

- $KEY(CSFCKI) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFCKM) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFDEC) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFENC) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFOWH) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFRNG) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFPKB) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFPKX) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFPKE) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFPKD) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFPKI) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFDSG) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW
- $KEY(CSFDSV) TYPE(CSF)
- UID(TCPIP-uid) SERVICE(READ) ALLOW

The following operator commands are required to complete the updates:
F ACF2,REBUILD(FAC)
F ACF2,REBUILD(CSF)

These commands and definitions assume that the default type code for CSFSERV resources is CSF."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25278r836664_chk'
  tag severity: 'medium'
  tag gid: 'V-223605'
  tag rid: 'SV-223605r836666_rule'
  tag stig_id: 'ACF2-TC-000070'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25266r836665_fix'
  tag 'documentable'
  tag legacy: ['V-97915', 'SV-107019']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
