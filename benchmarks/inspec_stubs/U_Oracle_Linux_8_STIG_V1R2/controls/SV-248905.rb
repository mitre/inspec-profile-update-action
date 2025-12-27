control 'SV-248905' do
  title 'OL 8 must not have the "iprutils" package installed if not required for operational support.'
  desc 'The "iprutils" package provides a suite of utilities to manage and configure IBM Power Linux RAID Adapters supported by the IPR SCSI storage device driver. Disabling the "iprutils" package protects the system against exploitation of any flaws in its implementation.'
  desc 'check', 'Determine if the "iprutils" package is installed with the following command: 
 
$ sudo yum list installed iprutils 
 
If the "iprutils" package is installed, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable non-essential capabilities by removing the "iprutils" package from the system with the following command: 
 
$ sudo yum remove iprutils'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52339r780279_chk'
  tag severity: 'medium'
  tag gid: 'V-248905'
  tag rid: 'SV-248905r780281_rule'
  tag stig_id: 'OL08-00-040380'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52293r780280_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
