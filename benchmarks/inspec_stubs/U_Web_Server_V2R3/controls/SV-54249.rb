control 'SV-54249' do
  title 'The log information from the web server must be protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of audit records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized deletion. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from deletion by non-privileged users.'
  desc 'check', 'Review the web server documentation and deployed configuration settings to determine if the web server logging features protect log information from unauthorized deletion.

Review file system settings to verify the log files have secure file permissions.

If the web server log files are not protected from unauthorized deletion, this is a finding.'
  desc 'fix', 'Configure the web server log files so unauthorized deletion of log information is not possible.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48069r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41672'
  tag rid: 'SV-54249r3_rule'
  tag stig_id: 'SRG-APP-000120-WSR-000070'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-47131r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
