control 'SV-96103' do
  title 'The WebSphere Application Server thread pool size must be defined according to application load requirements.'
  desc 'A thread pool enables components of the application server to reuse threads, which eliminates the need to create new threads at run time. Creating new threads expends system resources and can possibly lead to a DoS. Perform loading for your application to determine the required thread pool sizes.'
  desc 'check', 'Review System Security Plan documentation.

Identify the application thread pool size requirements defined by system owner. 

From the admin console navigate to Servers >> all servers >> [server name] >> ThreadPools.

Verify thread pool size according to specifications in documentation.

If the maximum size for each threadpool is set too large, and not set according to application requirements, this is a finding.'
  desc 'fix', 'Perform loading for your application to determine the required thread pool sizes.

To set thread pool size: 
From the admin console >> Servers >> all servers >> [server name] >> Additional Properties >> Select Thread Pools.

Set the thread pool size for each threadpool.'
  impact 0.5
  ref 'DPMS Target WebSphere AS 9.x'
  tag check_id: 'C-81099r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81389'
  tag rid: 'SV-96103r1_rule'
  tag stig_id: 'WBSP-AS-001590'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-88175r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
