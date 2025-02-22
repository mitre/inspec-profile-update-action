control 'SV-253552' do
  title 'Prisma Cloud Compute release tar distributions must have an associated SHA-256 digest.'
  desc "Each Prisma Cloud Compute release's tar file has an associated SHA-256 digest hash value to ensure the components have not been modified."
  desc 'check', %q(Offline Intelligence Stream:

If using Iron Bank distribution of Prisma Cloud Compute Console and Defenders, verify the Console and Defender imageID SHA256 values match the Palo Alto Networks published release values.

For the Console and Defender images, perform the following command:
$ docker inspect twistlock/private:console_22_01_839 | grep '"Image":'
            "Image": "sha256:dcd881fe9c796ed08867c242389737c4f2e8ab463377a90deddc0add4c3e8524",

If the imageID values do not match the published release SHA256 for the version of the image release, this is a finding. 

Note: Image tag will be the release number, e.g., console_22_01_839. Published release image sha values are published here: https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-compute-edition-public-sector/isolated_upgrades/releases.html)
  desc 'fix', 'Deploy the latest version from https://support.paloaltonetworks.com.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks Prisma Cloud Compute'
  tag check_id: 'C-57004r840492_chk'
  tag severity: 'medium'
  tag gid: 'V-253552'
  tag rid: 'SV-253552r879898_rule'
  tag stig_id: 'CNTR-PC-001770'
  tag gtitle: 'SRG-APP-000610-CTR-001385'
  tag fix_id: 'F-56955r840493_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
