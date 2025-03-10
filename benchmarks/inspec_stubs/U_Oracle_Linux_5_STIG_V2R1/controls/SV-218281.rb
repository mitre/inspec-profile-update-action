control 'SV-218281' do
  title 'The /etc/resolv.conf file must have mode 0644 or less permissive.'
  desc "The resolv.conf (or equivalent) file configures the system's DNS resolver.  DNS is used to resolve host names to IP addresses.  If DNS configuration is modified maliciously, host name resolution may fail or return incorrect information.  DNS may be used by a variety of system security functions such as time synchronization, centralized authentication, and remote system logging."
  desc 'check', 'Check the mode of the /etc/resolv.conf file.
# ls -l /etc/resolv.conf
If the file mode is not 0644, this is a finding.'
  desc 'fix', 'Change the mode of the /etc/resolv.conf file to 0644.
# chmod 0644 /etc/resolv.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19756r568726_chk'
  tag severity: 'medium'
  tag gid: 'V-218281'
  tag rid: 'SV-218281r603259_rule'
  tag stig_id: 'GEN001364'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19754r568727_fix'
  tag 'documentable'
  tag legacy: ['V-22321', 'SV-64185']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
