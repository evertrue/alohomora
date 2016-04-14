#!/usr/bin/env ruby

require 'json'
require 'awesome_print'
require 'base64'
require 'pbkdf2'

# [4] pry(main)> profile.keys
# => ["uuid",
#  "updatedAt",
#  "passwordHint",
#  "masterKey",
#  "iterations",
#  "lastUpdatedBy",
#  "profileName",
#  "salt",
#  "overviewKey",
#  "createdAt"]

def profile
  data = File.read('/Users/eherot/Dropbox/Apps/1Password/1Password.opvault/default/profile.js')
  idx = data.index '{'

  data = data[idx..-1]
  idx = data.index '}', -10
  profile_json = data[0..idx]

  JSON.parse profile_json
end

def verify_header(ciphertext)
  data = Base64.decode64(ciphertext)
  data = data[0..-33]
  data[0..7] == 'opdata01'
end

def decrypt(src, derived_enc_key, derived_mac_key)
  src = Base64.decode64(src)

  mac_src = src[-32..-1] # Last 32 chars
  src = src[0..-33] # All but last 32 chars

  printf("macKey: %s\n", Base64.encode64(derived_mac_key))
  printf("encKey: %s\n", Base64.encode64(derived_enc_key))
  printf("src: %s\n", src)
  printf("mac_src: %s\n", mac_src)

  hmac = OpenSSL::HMAC.digest 'sha256',
                              derived_mac_key,
                              src
  puts "mac_buf-base64: #{Base64.encode64(hmac)}"
  puts "mac_buf: #{hmac}"

  raise "Invalid opdata signature" unless mac_src == hmac

  # cipher = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
  # cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1("ABCDEFGHIJKL", "12345678", 1024, 256)
  # cipher.iv = iv
  # cipher.decrypt
  # data = cipher.update(encrypted_data)
  # data << cipher.final
  # data
end

def main
  pwd = ENV['MASTER_PW']
  # ap profile

  derived_key = PBKDF2.new do |p|
    p.password = pwd
    p.salt = Base64.decode64(profile['salt'])
    p.iterations = profile['iterations']
    p.hash_function = OpenSSL::Digest::SHA512.new
    p.key_length = 64
  end

  derived_key_bin = derived_key.bin_string
  printf("dk: %s\n", derived_key_bin)
  derived_enc_key = derived_key_bin[0..31]
  derived_mac_key = derived_key_bin[32..-1]
  # puts derived_key.bin_string.inspect

  # puts "Master Key: #{profile['masterKey']}"

  dec_master_key = decrypt(profile['masterKey'], derived_enc_key, derived_mac_key)

  raise 'Invalid opdata header' unless verify_header(profile['masterKey'])

  puts 'FINISHED'
end

main
