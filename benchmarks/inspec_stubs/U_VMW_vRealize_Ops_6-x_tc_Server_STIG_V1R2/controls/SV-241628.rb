control 'SV-241628' do
  title 'tc Server CaSa log files must be protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of audit records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized deletion. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from deletion by non-privileged users.'
  desc 'check', "At the command prompt, execute the following command:

ls -lR /storage/log/vcops/log/casa/* | grep -vE '(pid$)|ntp'  | awk '$3 !~ /^admin/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

chown admin:admin <file>

Note: Replace <file> with any listed files.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44904r683744_chk'
  tag severity: 'medium'
  tag gid: 'V-241628'
  tag rid: 'SV-241628r879578_rule'
  tag stig_id: 'VROM-TC-000305'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-44863r683745_fix'
  tag 'documentable'
  tag legacy: ['SV-99541', 'V-88891']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
