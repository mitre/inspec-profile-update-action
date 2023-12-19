control 'SV-255148' do
  title 'Samsung Android must be configured to enable encryption for data at rest on removable storage media or, alternately, the use of removable storage media must be disabled.'
  desc "The MOS must ensure the data being written to the mobile device's removable media is protected from unauthorized access. If data at rest is unencrypted, it is vulnerable to disclosure. Even if the operating system enforces permissions on data access, an adversary can read removable media directly, thereby circumventing operating system controls. Encrypting the data ensures confidentiality is protected even when the operating system is not running.

SFR ID: FMT_SMF_EXT.1.1 #20, #47d"
  desc 'check', 'Configure the Samsung Android devices to enable data at rest protection for removable media, or alternatively, disable their use.

This requirement is not applicable for devices that do not support removable storage media.

On the management tool, in the device restrictions, set "Mount physical media" to "Disallow".

This disables the use of all removable storage, e.g., micro SD cards, USB thumb drives, etc.

If the deployment requires the use of micro SD cards, KPE can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool,  in the device restrictions, set "Enforce external storage encryption" to "enable".'
  desc 'fix', 'Configure the Samsung Android devices to enable data at rest protection for removable media, or alternatively, disable their use.

This requirement is not applicable for devices that do not support removable storage media.

On the management tool, in the device restrictions, set "Mount physical media" to "Disallow".

This disables the use of all removable storage, e.g., micro SD cards, USB thumb drives, etc.

If the deployment requires the use of micro SD cards, KPE can be used to allow its usage in a STIG-approved configuration. In this case, do not configure the policy above, and instead:

On the management tool,  in the device restrictions, set "Enforce external storage encryption" to "enable".'
  impact 0.7
  ref 'DPMS Target Samsung Android OS 13 with Knox 3.x COPE'
  tag check_id: 'C-58761r873668_chk'
  tag severity: 'high'
  tag gid: 'V-255148'
  tag rid: 'SV-255148r873670_rule'
  tag stig_id: 'KNOX-13-210130'
  tag gtitle: 'PP-MDF-323100'
  tag fix_id: 'F-58705r873669_fix'
  tag 'documentable'
  tag cci: ['CCI-001199', 'CCI-002235']
  tag nist: ['SC-28', 'AC-6 (10)']
end
