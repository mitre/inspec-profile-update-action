control 'SV-845' do
  title 'The FTP daemon must be configured for logging or verbose mode.'
  desc 'Verbose FTP logging allows the examination of events involving FTP account activity, including login/logout events and file transfers.  Without this configuration, logs necessary for troubleshooting or analyzing security incidents will be incomplete.'
  desc 'check', 'Examine the FTP daemon service configuration.

# grep ftpd /etc/inetd.conf, 

Check the line for ftpd and determine if the -l or -v options are present.

If not, this is a finding.'
  desc 'fix', 'Edit the FTP daemon configuration in /etc/inetd.conf and add the "-l"  or "-v" options (as appropriate) to enable verbose logging.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-710r3_chk'
  tag severity: 'low'
  tag gid: 'V-845'
  tag rid: 'SV-845r2_rule'
  tag stig_id: 'GEN004980'
  tag gtitle: 'GEN004980'
  tag fix_id: 'F-999r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
