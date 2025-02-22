control 'SV-237924' do
  title 'The IBM z/VM SYSTEM CONFIG file must be configured to clear TDISK on IPL.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Examine the SYSTEM CONFIG file.

If the “Feature” statement specifies ENABLE CLEAR_TDISK, this is not a finding.'
  desc 'fix', 'Ensure that the following statement is in the SYSTEM CONFIG file:

FEATURES ENABLE CLEAR_TDISK

Further, before a minidisk is assigned to a user, the minidisk must be formatted to clear it of any residual data.

CMS FORMAT, ICKDSF, or any other low-level formatting program that erases all of the data on the minidisk may be used.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41134r649610_chk'
  tag severity: 'medium'
  tag gid: 'V-237924'
  tag rid: 'SV-237924r649612_rule'
  tag stig_id: 'IBMZ-VM-000710'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-41093r649611_fix'
  tag 'documentable'
  tag legacy: ['SV-93601', 'V-78895']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
