control 'SV-240777' do
  title 'tc Server HORIZON log files must be protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of audit records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized deletion. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from deletion by non-privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /storage/log/vmware/horizon

If any log files are not group-owned by "www", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

chown horizon:www /storage/log/vmware/horizon/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44010r674073_chk'
  tag severity: 'medium'
  tag gid: 'V-240777'
  tag rid: 'SV-240777r879578_rule'
  tag stig_id: 'VRAU-TC-000290'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-43969r674074_fix'
  tag 'documentable'
  tag legacy: ['SV-100639', 'V-89989']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
