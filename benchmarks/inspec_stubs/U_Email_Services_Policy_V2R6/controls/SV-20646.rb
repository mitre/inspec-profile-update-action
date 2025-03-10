control 'SV-20646' do
  title 'Email Administrator role must be assigned and authorized by the ISSO.'
  desc 'Separation of roles supports operational security for application as well as human resources. Roles accompanied by elevated privileges, such as that of the Email Administrator, must be carefully regulated and monitored.

All appointments to Information Assurance (IA) roles, such as Authorizing Officer (AO), System Security Manager (ISSM), and Information Systems Security Officer (ISSO) must be in writing, and include assigned duties and appointment criteria such as training, clearance and IT designation. The Email Administrator role is assigned and controlled by the ISSM. The ISSM role owns the responsibility to document responsibilities, privileges, training and scope for the Email Administrator role. It is with this definition that the ISSO is able to monitor assigned resources, ensuring that intended tasks are completed, and that elevated privileges are not used for purposes beyond their intended tasks.'
  desc 'check', 'Review the documented procedures for approval of Email Administrator Privileges. Review implementation evidence for the procedures. 

If the Email Administrator role is documented and authorized by the ISSO, this is not a finding.'
  desc 'fix', 'Establish a procedure that ensures the Email Administrator role is defined and authorized (assigned) as documented by the ISSO.'
  impact 0.3
  ref 'DPMS Target E-mail Services Policy'
  tag check_id: 'C-22458r6_chk'
  tag severity: 'low'
  tag gid: 'V-18865'
  tag rid: 'SV-20646r3_rule'
  tag stig_id: 'EMG0-056 EMail'
  tag gtitle: 'EMG0-056 E-mail Administrator Role'
  tag fix_id: 'F-19386r5_fix'
  tag 'documentable'
  tag responsibility: 'Other'
  tag ia_controls: 'DCSD-1'
end
