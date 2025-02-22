control 'SV-226968' do
  title 'The system must not have the UUCP service active.'
  desc 'The UUCP utility is designed to assist in transferring files, executing remote commands, and sending email between UNIX systems over phone lines and direct connections between systems. The UUCP utility is a primitive and arcane system with many security issues. There are alternate data transfer utilities/products that can be configured to more securely transfer data by providing for authentication,  as well as encryption.'
  desc 'check', '# svcs uucp

If UUCP is found enabled and its use is not justified and documented with the ISSO, this is a finding.'
  desc 'fix', '# svcadm disable uucp
# svcadm refresh inetd'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29130r485234_chk'
  tag severity: 'medium'
  tag gid: 'V-226968'
  tag rid: 'SV-226968r603265_rule'
  tag stig_id: 'GEN005280'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-29118r485235_fix'
  tag 'documentable'
  tag legacy: ['V-4696', 'SV-28428']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
