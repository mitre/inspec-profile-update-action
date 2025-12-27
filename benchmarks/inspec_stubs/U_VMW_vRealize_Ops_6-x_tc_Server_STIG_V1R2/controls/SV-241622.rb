control 'SV-241622' do
  title 'tc Server CaSa log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc 'check', %q(At the command prompt, execute the following command:

stat -c "%a %n" /storage/log/vcops/log/casa/* | awk '$1 !~ /^640/ && $2 ~ /(\.txt)|(\.log)/ {print}'

If the command produces any output, this is a finding.)
  desc 'fix', 'At the command prompt, execute the following commands:

sed -i "/^[^#]*UMASK/ c\\UMASK 027" /etc/login.defs

find /storage/log/vcops/log/casa/ -type f -exec chmod o=--- {} \\;'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44898r683726_chk'
  tag severity: 'medium'
  tag gid: 'V-241622'
  tag rid: 'SV-241622r879576_rule'
  tag stig_id: 'VROM-TC-000275'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-44857r683727_fix'
  tag 'documentable'
  tag legacy: ['SV-99529', 'V-88879']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
