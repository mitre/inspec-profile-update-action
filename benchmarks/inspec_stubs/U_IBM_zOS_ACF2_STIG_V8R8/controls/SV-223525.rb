control 'SV-223525' do
  title 'IBM z/OS FTP Server daemon must be defined with proper security parameters.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "From the ISPF Command enter:
ACF
SET LID
LIST LIKE(FTP-) SECTION(ALL) PROFILE(OMVS)
NOTE: The JCL member is typically named FTPD.

If all of the following are true, this is not a finding.

If any of the following is untrue, this is a finding.

The FTP daemon logonid is FTPD.
The FTPD logonid is defined with the STC attribute.
The FTPD logonid has the following z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh."
  desc 'fix', 'Define the FTP daemon to run under its own user account. Specifically, it does not share the account defined for the z/OS UNIX kernel.

Define the FTP Server daemon account, privileges, and access authorizations to the ACP using the requirements below.

The following commands can be used to create the user account that is required for the FTP daemon:

SET LID
INSERT FTPD NAME(FTPD) GROUP(STCTCPX) STC

SET PROFILE(USER) DIVISION(OMVS)
INSERT FTPD UID(0) HOME(/) PROGRAM(/bin/sh)

F ACF2,REBUILD(USR),CLASS(P)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25198r858865_chk'
  tag severity: 'medium'
  tag gid: 'V-223525'
  tag rid: 'SV-223525r861172_rule'
  tag stig_id: 'ACF2-FT-000090'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25186r504634_fix'
  tag 'documentable'
  tag legacy: ['SV-106859', 'V-97755']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
