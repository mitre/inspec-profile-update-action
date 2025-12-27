control 'SV-223569' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 for full disk encryption.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive, when used for backups) within an operating system.

This requirement addresses protection of user-generated data, as well as operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.

'
  desc 'check', "Determine if IBM's DS880 Disks are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25242r504728_chk'
  tag severity: 'medium'
  tag gid: 'V-223569'
  tag rid: 'SV-223569r533198_rule'
  tag stig_id: 'ACF2-OS-000340'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag fix_id: 'F-25230r504729_fix'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000405-GPOS-00184', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag legacy: ['V-97843', 'SV-106947']
  tag cci: ['CCI-001199', 'CCI-002450', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-13 b', 'SC-28 (1)', 'SC-28 (1)']
end
