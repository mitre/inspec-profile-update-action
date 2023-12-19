control 'SV-99539' do
  title 'tc Server UI log files must be protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of audit records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized deletion. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from deletion by non-privileged users.'
  desc 'check', "At the command prompt, execute the following command:

ls -lR /storage/log/vcops/log/product-ui/* | grep -vE 'pid$'  | awk '$3 !~ /^admin/ {print}'

If the command produces any output, this is a finding."
  desc 'fix', 'At the command prompt, execute the following command:

chown admin:admin <file>

Note: Replace <file> with any listed files.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88889'
  tag rid: 'SV-99539r1_rule'
  tag stig_id: 'VROM-TC-000300'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-95631r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
