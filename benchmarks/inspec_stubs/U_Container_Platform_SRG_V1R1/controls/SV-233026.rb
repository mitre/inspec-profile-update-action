control 'SV-233026' do
  title 'Least privilege access and need to know must be required to access the container platform registry.'
  desc 'The container platform registry is used to store images and is the keeper of truth for trusted images within the platform. To guarantee the images integrity, access to the registry must be limited to those individuals who need to perform tasks to the images such as the update, creation, or deletion of images. Without this control access, images can be deleted that are in use by the container platform causing a denial of service (DoS), and images can be modified or introduced without going through the testing and validation process allowing for the intentional or unintentional introduction of containers with flaws and vulnerabilities.'
  desc 'check', 'Review the container platform configuration to determine if least privilege and need-to-know access is being used for container platform registry access. 

If least privilege and need-to-know access is not being used for container platform registry access, this is a finding.'
  desc 'fix', 'Configure the container platform to use least privilege and need to know when granting access to the container platform registry. The fix ensures the proper roles and permissions are configured.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35962r599510_chk'
  tag severity: 'medium'
  tag gid: 'V-233026'
  tag rid: 'SV-233026r599511_rule'
  tag stig_id: 'SRG-APP-000033-CTR-000090'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-35930r598715_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
