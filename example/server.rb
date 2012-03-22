#!/usr/bin/env ruby
# -*- encoding: utf-8 -*-
=begin
Example of SRP server.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the Python Software Foundation nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL TOM COCAGNE BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

=end
require 'rubygems'
require 'sinatra'
require 'json'
require 'srp'
require 'logger'
logger = Logger.new $stdout

# set prime N length - client has to use the same value!
prime_length = 1024


# user_passwords contains {username => [password_verifier, salt]}
user_passwords = {}
{
  "leonardo"     => "capricciosa",
  "raphael"      => "quattro formaggi",
  "donatello"    => "margherita",
  "michelangelo" => "tropicana"
}.
  map { |username, raw_password|
    {username => SRP::Verifier.new(prime_length).generate_userauth(username, raw_password) }}.
  each {|h| user_passwords.update h}


# Upon identifying himself to the host, the client will receive the
# salt stored on the host under his username.
post '/authenticate' do
  username = params[:username]
  _user = user_passwords[username]
  unless _user
    logger.warn "User #{username} not found"
    halt 401
  end

  # authentication is two-stage process.

  # phase 1
  if params[:A]
    aa = params[:A]
    logger.info "#{username} requested authentication challenge"
    v = _user[:verifier]
    salt = _user[:salt]
    # server generates B, saves A and B to database
    srp = SRP::Verifier.new(prime_length)
    _session = srp.get_challenge_and_proof username, v, salt, aa
    # store proof to memory
    _user[:session_proof] = _session[:proof]
    #logger.debug _user[:session_proof]
    # server sends salt and B
    # DEBUG:
    # srp.verify_session(_session[:proof], "whatever")
    # logger.info "server M: #{srp.M}"
    return JSON.generate(_session[:challenge])

  # phase 2
  elsif params[:M]
    logger.info "#{username} provided challenge response"
    client_M = params[:M]
    logger.info "client M: #{client_M}"
    # retrive proof from database
    proof = _user[:session_proof]
    # verify
    srp = SRP::Verifier.new(prime_length)
    verification = srp.verify_session(proof, client_M)
    logger.info "server M: #{srp.M}"
    if verification
      # authenticated!
      logger.info "#{username} authenticated"
      logger.info "server H_AMK: #{srp.H_AMK}"
      return JSON.generate({:H_AMK => srp.H_AMK})
    end
  end

  halt 401
end
