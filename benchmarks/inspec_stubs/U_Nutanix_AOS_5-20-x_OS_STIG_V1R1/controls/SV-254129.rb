control 'SV-254129' do
  title 'Nutanix AOS must enforce discretionary access control on symlinks and hardlinks.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

'
  desc 'check', 'Confirm Nutanix AOS enforces discretionary access control on symlinks and hardlinks.

$ sudo sysctl fs.protected_symlinks
fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1" or is missing, this is a finding.

Check the status of the fs.protected_hardlinks kernel parameter.

$ sudo sysctl fs.protected_hardlinks
fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to allow operating system admins to pass information to other operating system admins or users adding or modifying the following line(s) in the system configuration file /etc/syscrl.d/

fs.protected_symlinks = 1
fs.protected_hardlinks = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57614r846473_chk'
  tag severity: 'medium'
  tag gid: 'V-254129'
  tag rid: 'SV-254129r846475_rule'
  tag stig_id: 'NUTX-OS-000170'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-57565r846474_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000312-GPOS-00123', 'SRG-OS-000312-GPOS-00124']
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
