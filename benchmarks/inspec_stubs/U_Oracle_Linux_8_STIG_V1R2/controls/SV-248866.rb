control 'SV-248866' do
  title 'All OL 8 networked systems must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and read or altered.  
 
This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.  
 
Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, logical means (cryptography) do not have to be employed, and vice versa.

'
  desc 'check', 'Verify SSH is installed with the following command:

$ sudo yum list installed openssh-server

openssh-server.x86_64                 8.0p1-5.el8          @anaconda

If the "SSH server" package is not installed, this is a finding.'
  desc 'fix', 'Install SSH packages onto the host with the following command:

$ sudo yum install openssh-server.x86_64'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52300r780162_chk'
  tag severity: 'medium'
  tag gid: 'V-248866'
  tag rid: 'SV-248866r780164_rule'
  tag stig_id: 'OL08-00-040159'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag fix_id: 'F-52254r780163_fix'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'SC-8 (2)']
end
