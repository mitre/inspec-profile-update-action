control 'SV-217094' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network routers presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled router. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the router configuration to determine if received MSDP packets are authenticated.

protocols {
    msdp {
        group AS25 {
            peer 5.5.5.5 {
                authentication-key "$8$KspW87GUH.mTxNfz"; ## SECRET-DATA}
        }
    }

If the router does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Configure the router to authenticate MSDP messages as shown in the following example:

[edit protocols msdp group AS25 peer 5.5.5.5]
set authentication-key xxxxxxxx'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18323r297150_chk'
  tag severity: 'medium'
  tag gid: 'V-217094'
  tag rid: 'SV-217094r639663_rule'
  tag stig_id: 'JUNI-RT-000900'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-18321r297151_fix'
  tag 'documentable'
  tag legacy: ['SV-101181', 'V-90971']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
