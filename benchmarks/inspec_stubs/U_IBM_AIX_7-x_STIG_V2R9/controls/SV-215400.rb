control 'SV-215400' do
  title 'AIX must allow admins to send a message to all the users who logged in currently.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read or write). Ownership is usually acquired as a consequence of creating the object or via specified ownership assignment. DAC allows the owner to determine who will have access to objects they control. An example of DAC includes user-controlled file permissions.

When discretionary access control policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects. A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level. The policy is bounded by the information system boundary. Once the information is passed outside the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of discretionary access control require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', 'Run following command to see if wall command is installed:
# ls -al /usr/sbin/wall

If "/usr/sbin/wall" does not exist, this is a finding.'
  desc 'fix', 'Install the "bos.rte.misc_cmds" package from AIX DVD Volume 1 using the following command (assuming that the DVD device is /dev/cd0):
# installp -aXYgd /dev/cd0 -e /tmp/install.log bos.rte.misc_cmds'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16598r294651_chk'
  tag severity: 'medium'
  tag gid: 'V-215400'
  tag rid: 'SV-215400r853489_rule'
  tag stig_id: 'AIX7-00-003098'
  tag gtitle: 'SRG-OS-000312-GPOS-00122'
  tag fix_id: 'F-16596r294652_fix'
  tag 'documentable'
  tag legacy: ['SV-101603', 'V-91505']
  tag cci: ['CCI-002164', 'CCI-002165']
  tag nist: ['AC-3 (4)', 'AC-3 (4)']
end
