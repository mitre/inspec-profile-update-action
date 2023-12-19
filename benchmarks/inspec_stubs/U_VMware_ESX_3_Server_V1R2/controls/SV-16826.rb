control 'SV-16826' do
  title 'ISO images do not have hash checksums.'
  desc 'Since ISO operating system images are typically large files, transferring these ISO operating system images over the network may cause corruption to the files. There are simple ways to check the integrity of the file on both the source and destination system using hashing algorithms. Users should create hash checksums on all ISO operating system images on the ESX Server before utilizing the ISO operating system image for virtual machines.'
  desc 'check', 'On the ESX Server service console go to the partition that stores the ISO images and verify hash checksums are present for any ISO files.  Perform the following to determine if ISO images are verified for integrity:

# ls -al /vmimages (Or the name of the ISO partition) 

If no sha1sums are returned or the number of ISO images is different from the number of sha1sums, this is a finding.'
  desc 'fix', 'Create SHA1 checksums for all ISO images.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16244r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15885'
  tag rid: 'SV-16826r1_rule'
  tag stig_id: 'ESX0890'
  tag gtitle: 'ISO images do not have hash checksums'
  tag fix_id: 'F-15845r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Machine Administrator]', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCNR-1, ECTM-1, ECTM-2'
end
