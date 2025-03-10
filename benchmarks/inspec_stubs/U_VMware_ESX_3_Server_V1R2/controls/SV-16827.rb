control 'SV-16827' do
  title 'ISO images are not verified for integrity when moved across the network.'
  desc 'Since ISO operating system images are typically large files, transferring these ISO operating system images over the network may cause corruption to the files. There are simple ways to check the integrity of the file on both the source and destination system using hashing algorithms. Users should create hash checksums on all ISO operating system images on the ESX Server before utilizing the ISO operating system image for virtual machines.'
  desc 'check', 'On the ESX Server service console go to the partition that stores the ISO images and verify hash checksums are present for any ISO files.  Perform the following to determine if ISO images are verified for integrity:

# cd /vmimages (Or location of ISO images) && ls -al
# cat iso_sha1sum_file (Where this is the sha1sum file of ISO file) 
# sha1sum Filename.iso – ISO file

OR

#Sha1sum –c iso_sha1sum_file
Filename.iso : OK

Examples:

# cat Redhat.iso.sha1
da39a3ee5e6b4b0d3255bfef95601890afd80709 Redhat.iso

# sha1sum Redhat.iso
da39a3ee5e6b4b0d3255bfef95601890afd80709 Redhat.iso

OR

# sha1sum –c Redhat.iso.sha1
Redhat.iso : OK 

Compare the sha1sum against each other to ensure they are the same.  If they are not the same, this is a finding.'
  desc 'fix', 'Verify all SHA1 checksums for all ISO images.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16245r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15886'
  tag rid: 'SV-16827r1_rule'
  tag stig_id: 'ESX0900'
  tag gtitle: 'ISO images are not verified for integrity'
  tag fix_id: 'F-15846r1_fix'
  tag 'documentable'
  tag responsibility: ['[Virtual Machine Administrator]', 'Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'DCNR-1, ECTM-1, ECTM-2'
end
