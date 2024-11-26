control 'SV-13613' do
  title 'Private IP space is used within an Enclave without the use of split DNS to prevent private IPs from leaking into the public DNS system.'
  desc 'DNS operators should assume that any data placed in the DNS would be available to anyone connected to the Internet. Split DNS shall not be considered a mitigating factor or technique to deny DNS information to an attacker. Split DNS will continue to be required in one situation only: to prevent address space that is private (e.g., 10.0.0.0/24) or is otherwise concealed by some form of Network Address Translation from leaking into the public DNS system.'
  desc 'check', 'This check is only applicable if the site is using private IP space within the Enclave.  This is typically encountered when a site is using Network Address Translation (NAT) with private or non-routable IPs.

BIND
This configuration should be evidenced by the use of the view statement in the named.conf file.  If it is not, then the DNS administrator must satisfactorily explain how an alternative mechanism achieves the same effect. If the site employs NAT and a split DNS configuration is not employed or a satisfactory alternative mechanism is not employed, then this is a finding.  The objective is that an external DNS client should have no means of querying the DNS to obtain a host-to-IP-address mapping for an internal host that has a private or non-routable IP.

Windows
Review each zone and search for any private IP addresses. If private addresses are being utilized internally and their respective domain names are also capable of being accessed from outside the enclave, then ask the DNS administrator to explain if they are implementing a split DNS configuration.  Note:  Split DNS can also be referred to as split-horizon and split-brain DNS.  The best approach is to maintain separate servers for the external/internal zone records.  Most other approaches involve forwarding from the internal server, which is against the STIG guidelines.'
  desc 'fix', 'The IAO will ensure, when using private IP address space within an Enclave, that a split-DNS configuration is implemented to prevent the private address space from leaking into the public DNS system.'
  impact 0.3
  ref 'DPMS Target DNS Policy'
  tag check_id: 'C-3428r1_chk'
  tag severity: 'low'
  tag gid: 'V-13045'
  tag rid: 'SV-13613r1_rule'
  tag stig_id: 'DNS0215'
  tag gtitle: 'Split DNS not implemented for private IPs space.'
  tag fix_id: 'F-4350r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1'
end
