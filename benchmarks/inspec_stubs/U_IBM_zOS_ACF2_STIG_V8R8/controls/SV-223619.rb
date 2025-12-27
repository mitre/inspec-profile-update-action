control 'SV-223619' do
  title 'IBM z/OS UNIX resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET RESOURCE(SUR)
SET VERBOSE
LIST LIKE(BPX-)

If the ACF2 rules for all BPX.SRV.user TYPE(SUR) resources specify a default access of NONE, this is not a finding.

If the ACF2 rules for all BPX.SRV.user TYPE(SUR) resources restrict access to system software processes (e.g., web servers) that act as servers under z/OS UNIX, this is not a finding.

If the ACF2 rules for all BPX.SRV.user SURROGAT resources restrict access to authorized users identified in the  Site Security Plan, this is not a finding.'
  desc 'fix', 'Configure BPX. SRV.userid resources to be properly protected and access restricted to appropriate system tasks or systems programming personnel.

SURROGAT class BPX resources are used in conjunction with server applications that are performing tasks on behalf of client users that may not supply an authenticator to the server. This can be the case when clients are otherwise validated or when the requested service is performed from userids representing groups.

The default access for each BPX.SRV.userid resource must be no access. Access can be permitted only to system software processes that act as servers under OS/390 UNIX (e.g., web servers) and users whose access an approval are identified in the Site Security Plan.

Example:
SET R(SUR)
$KEY(BPX) TYPE(SUR) 
SRV.INTERNAL UID(FJB****STC******IMWEBSRV) SERVICE(READ) LOG
SRV.PRIVATE UID(FJB****STC******IMWEBSRV) SERVICE(READ) LOG 
SRV.PUBLIC UID(FJB****STC******IMWEBSRV) SERVICE(READ) LOG 
SRV.WEBADM UID(FJB****STC******IMWEBSRV) SERVICE(READ) LOG 
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25292r767071_chk'
  tag severity: 'medium'
  tag gid: 'V-223619'
  tag rid: 'SV-223619r853564_rule'
  tag stig_id: 'ACF2-US-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25280r767072_fix'
  tag 'documentable'
  tag legacy: ['SV-107047', 'V-97943']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
