control 'SV-253136' do
  title 'TOSS must enable kernel parameters to enforce discretionary access control on symlinks.'
  desc %q(Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.

By enabling the fs.protected_symlinks kernel parameter, symbolic links are permitted to be followed only when outside a sticky world-writable directory, or when the UID of the link and follower match, or when the directory owner matches the symlink's owner. Disallowing such symlinks helps mitigate vulnerabilities based on insecure file system accessed by privileged programs, avoiding an exploitation vector exploiting unsafe use of open() or creat().

)
  desc 'check', 'Verify the operating system is configured to enable DAC on symlinks with the following commands:

Check the status of the fs.protected_symlinks kernel parameter.

$ sudo sysctl fs.protected_symlinks

fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1" or is missing, this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -r fs.protected_symlinks /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf:fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the operating system to enable DAC on symlinks.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

fs.protected_symlinks = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56589r825078_chk'
  tag severity: 'medium'
  tag gid: 'V-253136'
  tag rid: 'SV-253136r825080_rule'
  tag stig_id: 'TOSS-04-040950'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-56539r825079_fix'
  tag satisfies: ['SRG-OS-000312-GPOS-00122', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag cci: ['CCI-002165', 'CCI-002235']
  tag nist: ['AC-3 (4)', 'AC-6 (10)']
end
