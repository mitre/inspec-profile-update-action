control 'SV-223559' do
  title 'IBM z/OS DFSMS control data sets must reside on separate storage volumes.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Review the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), to identify the fully qualified file names for the following SMS data sets:
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)

If the COMMDS and ACDS SMS data sets identified above reside on different volumes, this is not a finding.

If the COMMDS and ACDS SMS data sets identified above are collocated on the same volume, this is a finding.'
  desc 'fix', 'Allocate the primary and backup SMS Control data sets on separate volumes.

Source Control Data Set (SCDS) contains a SMS configuration, which defines a storage management policy.

 Active Control Data Set (ACDS) contains a copy of the most recently activated configuration. All systems in a SMS complex use this configuration to manage storage.

Communications Data Set (COMMDS) contains the name of the ACDS containing the currently active storage management policy, the current utilization statistics for each system managed volume, and other system information.

The ACDS data set will reside on a different volume than the COMMDS data set.

Allocate backup copies of the ADCS and COMMDS data sets on a different shared volume from the primary ACDS and COMMDS data sets.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25232r504704_chk'
  tag severity: 'medium'
  tag gid: 'V-223559'
  tag rid: 'SV-223559r533198_rule'
  tag stig_id: 'ACF2-OS-000230'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25220r504705_fix'
  tag 'documentable'
  tag legacy: ['V-97823', 'SV-106927']
  tag cci: ['CCI-000366', 'CCI-000549']
  tag nist: ['CM-6 b', 'CP-9 (6)']
end
