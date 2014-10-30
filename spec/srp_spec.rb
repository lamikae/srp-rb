# -*- encoding: utf-8 -*-
=begin

Copyright (c) 2012, Mikael Lammentausta
All rights reserved.

Following is the New BSD license:

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
require 'srp'

# monkey-patch API to define a, b and salt presetters
class SRP::Verifier
  def set_b val
    @b = val
  end
  def set_salt val
    @salt = val
  end
end
class SRP::Client
  def set_a val
    @a = val
  end
end

describe SRP do
  ###
  ### Test SRP functions.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 256 bit values.
  ###
  context "@module-functions" do
    before :all do
      @N = "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3".to_i(16)
      @g = 2
      @username = "user"
      @password = "password"
      @salt = "16ccfa081895fe1ed0bb"
      @a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2".to_i(16)
      @b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96".to_i(16)
    end

    it "should calculate k" do
      k = SRP.calc_k(@N, @g)
      ("%x" % k).should == "a392656346edfb80b491d15a1bdadf29e8b2c289b72cd06c9cf940240bcf9b2e"
      ("%b" % k).length.should == 256
    end

    it "should calculate x" do
      x = SRP.calc_x(@username, @password, @salt)
      ("%x" % x).should == "b115784c3d5ae8e7573eb9879b7e18b66a876ff2201bd57abf7890aee82414e"
      ("%b" % x).length.should == 252
    end

    it "should calculate verifier" do
      x = "bdd0a4e1c9df4082684d8d358b8016301b025375".to_i(16)
      v = SRP.calc_v(x, @N, @g)
      ("%x" % v).should == "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309"
      ("%b" % v).length.should == 256
    end

    it "should calculate u" do
      aa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      bb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      u = SRP.calc_u(aa, bb, @N)
      ("%x" % u).should == "72d40e5bbec6e7efc547cbdac99c7338bd8551ae8a9a305370f5c26df84c990b"
      ("%b" % u).length.should == 255
    end

    it "should calculate public client value A" do
      aa = SRP.calc_A(@a, @N, @g)
      ("%x" % aa).should == "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      ("%b" % aa).length.should == 256
    end

    it "should calculate public server value B" do
      k = "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50".to_i(16)
      v = "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309".to_i(16)
      bb = SRP.calc_B(@b, k, v, @N, @g)
      ("%x" % bb).should == "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      ("%b" % bb).length.should == 256
    end

    it "should calculate session key from client params" do
      bb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68".to_i(16)
      k = "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50".to_i(16)
      x = "bdd0a4e1c9df4082684d8d358b8016301b025375".to_i(16)
      u = "c60b17ddf568dd5743d0e3ba5621646b742432c5".to_i(16)
      a = @a
      ss = SRP.calc_client_S(bb, a, k, x, u, @N, @g)
      ("%x" % ss).should == "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      ("%b" % ss).length.should == 256
    end

    it "should calculate session key from server params" do
      aa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e".to_i(16)
      v = "ce36e101ed8c37ed98ba4e441274dabd1062f3440763eb98bd6058e5400b6309".to_i(16)
      u = "c60b17ddf568dd5743d0e3ba5621646b742432c5".to_i(16)
      b = @b
      ss = SRP.calc_server_S(aa, b, v, u, @N)
      ("%x" % ss).should == "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      ("%b" % ss).length.should == 256
    end

    it "should calculate M" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xbb = "fbc56086bb51e26ee1a8287c0a7f3fd4e067e55beb8530b869b10b961957ff68"
      xss = "a606c182e364d2c15f9cdbeeeb63bb00c831d1da65eedc1414f21157d0312a5a"
      xkk = SRP.sha3_hex(xss)
      xkk.should == "f5d30d2ed8686461fc8626357237d6ee03eeeb3e570546cb62081836fdc34df3"
      mm = SRP.calc_M(@username, @salt, xaa, xbb, xkk, @N, @g)
      ("%x" % mm).should == "bff08229b28c09021c0889019cbecbea5e19ac1eee2ec102ea891f2af43647f9"
    end

    it "should calculate H(AMK)" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xmm = "bff08229b28c09021c0889019cbecbea5e19ac1eee2ec102ea891f2af43647f9"
      xkk = "f5d30d2ed8686461fc8626357237d6ee03eeeb3e570546cb62081836fdc34df3"
      h_amk = SRP.calc_H_AMK(xaa, xmm, xkk, @N, @g)
      ("%x" % h_amk).should == "7ba4dd18f68685fa2eb64c474373205160a42aa3e5d4e10e8dd72bd8a4137c77"
    end
  end


  ###
  ### Test predefined values for N and g.
  ### Values are from vectors listed in RFC 5054 Appendix B.
  ###
  context "@predefined-Ng" do
    it "should be 1024 bits" do
      srp = SRP::Verifier.new(1024)
      nn = srp.N
      ("%x" % nn).should == "eeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3"
      ("%b" % nn).length.should == 1024
      srp.g.should == 2
    end

    it "should be 1536 bits" do
      srp = SRP::Verifier.new(1536)
      nn = srp.N
      ("%b" % nn).length.should == 1536
      srp.g.should == 2
    end

    it "should be 2048 bits" do
      srp = SRP::Verifier.new(2048)
      nn = srp.N
      ("%b" % nn).length.should == 2048
      srp.g.should == 2
    end

    it "should be 3072 bits" do
      srp = SRP::Verifier.new(3072)
      nn = srp.N
      ("%b" % nn).length.should == 3072
      srp.g.should == 5
    end

    it "should be 4096 bits" do
      srp = SRP::Verifier.new(4096)
      nn = srp.N
      ("%b" % nn).length.should == 4096
      srp.g.should == 5
    end

    it "should be 6144 bits" do
      srp = SRP::Verifier.new(6144)
      nn = srp.N
      ("%b" % nn).length.should == 6144
      srp.g.should == 5
    end

    it "should be 8192 bits" do
      srp = SRP::Verifier.new(8192)
      nn = srp.N
      ("%b" % nn).length.should == 8192
      srp.g.should == 19
    end
  end


  ###
  ### Test server-side Verifier.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 1024 bit values.
  ###
  context "@verifier" do
    before :all do
      @username = "user"
      @password = "password"
      @salt = "16ccfa081895fe1ed0bb"
      @a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2"
      @b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"
    end

    it "should calculate k" do
      k = SRP::Verifier.new(1024).k
      k.should == 42563213017296497916222366315348678499853045336041860736166442636932729927292
    end

    it "should generate salt and verifier" do
      auth = SRP::Verifier.new(1024).generate_userauth(@username, @password)
      auth[:username].should == @username
      auth[:verifier].should be
      auth[:salt].should be
    end

    it "should calculate verifier with given salt" do
      srp = SRP::Verifier.new(1024)
      srp.set_salt @salt
      auth = srp.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      salt.should == @salt
      v.should == "89a0c9a18add0f80c0d03725bf37791f854310756c1d54e5d369ff52b21bc49ebabe7cbcb8e237f9515a175aba8e5be10d855dcfedd3cdaa465fdd51d158889a98d52ab9a62014080ef2f26769a02b3ae64ed378744fc0affedddc26e2a3cc41c020469d95c3a0aff91ff87409a8b4c0c3bd73f2b264b6edb5e5305d2847e764"
    end

    it "should generate salt and calculate verifier" do
      srp = SRP::Verifier.new(1024)
      auth = srp.generate_userauth(@username, @password)
      v = auth[:verifier]
      salt = auth[:salt]
      ("%b" % v.to_i(16)).length.should >= 1000
      ("%b" % salt.to_i(16)).length.should >= 50
    end

    it "should generate B with predefined b" do
      v = "89a0c9a18add0f80c0d03725bf37791f854310756c1d54e5d369ff52b21bc49ebabe7cbcb8e237f9515a175aba8e5be10d855dcfedd3cdaa465fdd51d158889a98d52ab9a62014080ef2f26769a02b3ae64ed378744fc0affedddc26e2a3cc41c020469d95c3a0aff91ff87409a8b4c0c3bd73f2b264b6edb5e5305d2847e764"
      srp = SRP::Verifier.new(1024)
      srp.set_b @b.to_i(16)
      bb = srp.generate_B(v)
      bb.should == "a638527ee7eeb0488bd73c564578e0f95852ecaf72ef62ae10c9b847da5d7bc4229ecdbb49dc0ff29ce63f6c3731ba03256d4a6ecf219972a65df9d79c1ac04998b961ff21c429883014f89717a54c822d82b316dbb199d241e67ce43ea6b20776c13aa6098b5d3cb12ff5d78ae7c77d215541980da389b24ef525fb8eace617"
    end

     it "should generate B" do
      srp = SRP::Verifier.new(1024)
      bb = srp.generate_B("0")
      ("%b" % bb.to_i(16)).length.should >= 1000
      ("%b" % srp.b).length.should > 200
    end

    it "should calculate server session and key" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "a638527ee7eeb0488bd73c564578e0f95852ecaf72ef62ae10c9b847da5d7bc4229ecdbb49dc0ff29ce63f6c3731ba03256d4a6ecf219972a65df9d79c1ac04998b961ff21c429883014f89717a54c822d82b316dbb199d241e67ce43ea6b20776c13aa6098b5d3cb12ff5d78ae7c77d215541980da389b24ef525fb8eace617"
      # v is from db
      v = "89a0c9a18add0f80c0d03725bf37791f854310756c1d54e5d369ff52b21bc49ebabe7cbcb8e237f9515a175aba8e5be10d855dcfedd3cdaa465fdd51d158889a98d52ab9a62014080ef2f26769a02b3ae64ed378744fc0affedddc26e2a3cc41c020469d95c3a0aff91ff87409a8b4c0c3bd73f2b264b6edb5e5305d2847e764"
      _proof = {:A => aa, :B => bb, :b => @b,
        :I => @username, :s => @salt, :v => v}
      srp = SRP::Verifier.new(1024)
      srp.verify_session(_proof, "match insignificant")
      ss = srp.S
      ss.should == "1937e05f33c3b5811b38968aae84a5abfaf0477c3ba91584fb88866e4ccb67a759be937e329c08b71a304521d4ed92e7e65bf48826faa6987a13dc050e62ae772c6f97fe7218de53c1dbe215a7f934555d9da22543f73ae47aea7484fbe2e335464c9574c4b9a88e12d77e98a0b24a84581df355fbdbd1d2c15518341e0df966"
      kk = srp.K
      kk.should == "cfb7ee28c9c6539483482e71d7bd35898dd3e8de0f014a9d63a9b52d380623b7"
    end

    it "should calculate verifier M and server proof" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "a638527ee7eeb0488bd73c564578e0f95852ecaf72ef62ae10c9b847da5d7bc4229ecdbb49dc0ff29ce63f6c3731ba03256d4a6ecf219972a65df9d79c1ac04998b961ff21c429883014f89717a54c822d82b316dbb199d241e67ce43ea6b20776c13aa6098b5d3cb12ff5d78ae7c77d215541980da389b24ef525fb8eace617"
      # v is from db
      v = "89a0c9a18add0f80c0d03725bf37791f854310756c1d54e5d369ff52b21bc49ebabe7cbcb8e237f9515a175aba8e5be10d855dcfedd3cdaa465fdd51d158889a98d52ab9a62014080ef2f26769a02b3ae64ed378744fc0affedddc26e2a3cc41c020469d95c3a0aff91ff87409a8b4c0c3bd73f2b264b6edb5e5305d2847e764"
      # S is validated
      ss = "1937e05f33c3b5811b38968aae84a5abfaf0477c3ba91584fb88866e4ccb67a759be937e329c08b71a304521d4ed92e7e65bf48826faa6987a13dc050e62ae772c6f97fe7218de53c1dbe215a7f934555d9da22543f73ae47aea7484fbe2e335464c9574c4b9a88e12d77e98a0b24a84581df355fbdbd1d2c15518341e0df966"
      # K = H(S)
      kk = SRP.sha3_hex(ss)
      client_M = "2e622470344d2ef11a36dc82227bbd0023b80f28004c5cb71d04e659b968ee8f"
      _proof = {:A => aa, :B => bb, :b => @b,
        :I => @username, :s => @salt, :v => v}
      srp = SRP::Verifier.new(1024)
      srp.verify_session(_proof, client_M)
      srp.M.should == client_M
      srp.H_AMK.should == "7e413ee435bd3668179d941c3ef33a992bb2d2e5286161b440921d92346e5c03"
    end
  end


  ###
  ### Test Client.
  ### Values are from http://srp.stanford.edu/demo/demo.html
  ### using 1024 bit values.
  ###
  context "@client" do
    before :all do
      @username = "user"
      @password = "password"
      @salt = "16ccfa081895fe1ed0bb"
      @a = "7ec87196e320a2f8dfe8979b1992e0d34439d24471b62c40564bb4302866e1c2"
      @b = "8143e2f299852a05717427ea9d87c6146e747d0da6e95f4390264e55a43ae96"
    end

    it "should generate A from random a" do
      srp = SRP::Client.new(1024)
      aa1 = srp.generate_A
      ("%b" % aa1.to_i(16)).length.should >= 1000
      ("%b" % srp.generate_A.to_i(16)).length.should >= 200
      srp = SRP::Client.new(1024)
      aa2 = srp.generate_A
      ("%b" % aa2.to_i(16)).length.should >= 1000
      ("%b" % srp.generate_A.to_i(16)).length.should >= 200
      aa1.should_not == aa2
    end

    it "should calculate A" do
      srp = SRP::Client.new(1024)
      srp.set_a @a.to_i(16)
      aa = srp.generate_A
      aa.should == "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
    end

    it "should calculate client session and key" do
      srp = SRP::Client.new(1024)
      srp.set_a @a.to_i(16)
      aa = srp.generate_A # created in phase 1
      bb = "a638527ee7eeb0488bd73c564578e0f95852ecaf72ef62ae10c9b847da5d7bc4229ecdbb49dc0ff29ce63f6c3731ba03256d4a6ecf219972a65df9d79c1ac04998b961ff21c429883014f89717a54c822d82b316dbb199d241e67ce43ea6b20776c13aa6098b5d3cb12ff5d78ae7c77d215541980da389b24ef525fb8eace617"
      mm = srp.process_challenge(@username, @password, @salt, bb)
      ss = srp.S
      ss.should == "1937e05f33c3b5811b38968aae84a5abfaf0477c3ba91584fb88866e4ccb67a759be937e329c08b71a304521d4ed92e7e65bf48826faa6987a13dc050e62ae772c6f97fe7218de53c1dbe215a7f934555d9da22543f73ae47aea7484fbe2e335464c9574c4b9a88e12d77e98a0b24a84581df355fbdbd1d2c15518341e0df966"
      kk = srp.K
      kk.should == "cfb7ee28c9c6539483482e71d7bd35898dd3e8de0f014a9d63a9b52d380623b7"
    end
  end


  ###
  ### Simulate actual authentication scenario over HTTP
  ### when the server is RESTful and has to persist authentication
  ### state between challenge and response.
  ###
  context "@authentication" do
    before :all do
      @username = "leonardo"
      password = "icnivad"
      @auth = SRP::Verifier.new(1024).generate_userauth(@username, password)
      # imitate database persistance layer
      @db = {@username => {
        :verifier => @auth[:verifier],
        :salt     => @auth[:salt],
        }}
    end

    it "should authenticate" do
      client = SRP::Client.new(1024)
      verifier = SRP::Verifier.new(1024)
      # phase 1
      # (client)
      aa = client.generate_A
      # (server)
      v = @auth[:verifier]
      salt = @auth[:salt]
      bb = verifier.generate_B v
      b = "%x" % verifier.b
      # phase 2
      # (client)
      client_M = client.process_challenge(@username, "icnivad", salt, bb)
      # (server)
      _proof = {:A => aa, :B => bb, :b => b, :I => @username, :s => salt, :v => v}
      server_H_AMK = verifier.verify_session(_proof, client_M)
      server_H_AMK.should be
      # (client)
      client.H_AMK.should == server_H_AMK
    end

    it "should not authenticate" do
      client = SRP::Client.new(1024)
      verifier = SRP::Verifier.new(1024)
      # phase 1
      # (client)
      aa = client.generate_A
      # (server)
      v = @auth[:verifier]
      salt = @auth[:salt]
      bb = verifier.generate_B v
      b = "%x" % verifier.b
      # phase 2
      # (client)
      client_M = client.process_challenge(@username, "wrong password", salt, bb)
      # (server)
      _proof = {:A => aa, :B => bb, :b => b, :I => @username, :s => salt, :v => v}
      verifier.verify_session(_proof, client_M).should == false
      verifier.H_AMK.should_not be
    end

    it "should be applied in async authentication with stateless server" do
      username = @username

      # client generates A and begins authentication process
      client = SRP::Client.new(1024)
      aa = client.start_authentication()


      #
      # username and A are received  (client --> server)
      #

      # server finds user from "database"
      _user = @db[username]
      _user.should_not be_nil
      v = _user[:verifier]
      salt = _user[:salt]

      # server generates B, saves A and B to database
      srp = SRP::Verifier.new(1024)
      _session = srp.get_challenge_and_proof username, v, salt, aa
      _session[:challenge][:B].should == srp.B
      _session[:challenge][:salt].should == salt
      # store proof to memory
      _user[:session_proof] = _session[:proof]
      # clear variables to simulate end of phase 1
      srp = username = v = bb = salt = nil
      # server sends salt and B
      client_response = _session[:challenge]


      #
      # client receives B and salt  (server --> client)
      #
      bb = client_response[:B]
      salt = client_response[:salt]
      # client generates session key
      # at this point _client_srp.a should be persisted!! calculate_client_key is stateful!
      mmc = client.process_challenge @username, "icnivad", salt, bb
      client.A.should be
      client.M.should == mmc
      client.K.should be
      client.H_AMK.should be
      # client sends M --> server
      client_M = client.M

      #
      # server receives client session key  (client --> server)
      #
      username = @username
      _user = @db[username]
      # retrive session from database
      proof = _user[:session_proof]
      srp = SRP::Verifier.new(1024)
      verification = srp.verify_session(proof, client_M)
      verification.should_not == false

      # Now the two parties have a shared, strong session key K.
      # To complete authentication, they need to prove to each other that their keys match.

      client.verify(verification).should == true
      verification.should == client.H_AMK
    end
  end
end
