control 'SV-233027' do
  title 'Least privilege access and need to know must be required to access the container platform runtime.'
  desc 'The container platform runtime is used to instantiate containers. If this process is accessed by those persons who are not authorized, those containers offering services can be brought to a denial of service (DoS) situation, disabling a large number of services with a small change to the container platform. To limit this threat, it is important to limit access to the runtime to only those individuals with runtime duties.'
  desc 'check', 'Review the container platform to determine if only those individuals with runtime duties have access to the container platform runtime. 

If users have access to the container platform runtime that do not have runtime duties, this is a finding.'
  desc 'fix', 'Configure the container platform to use least privilege and need to know when granting access to the container runtime. The fix ensures the proper roles and permissions are configured.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35963r598717_chk'
  tag severity: 'medium'
  tag gid: 'V-233027'
  tag rid: 'SV-233027r599509_rule'
  tag stig_id: 'SRG-APP-000033-CTR-000095'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-35931r598718_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
