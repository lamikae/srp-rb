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
      ("%x" % k).should == "dbe5dfe0704fee4c85ff106ecd38117d33bcfe50"
      ("%b" % k).length.should == 160
    end

    it "should calculate x" do
      x = SRP.calc_x(@username, @password, @salt)
      ("%x" % x).should == "bdd0a4e1c9df4082684d8d358b8016301b025375"
      ("%b" % x).length.should == 160
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
      ("%x" % u).should == "c60b17ddf568dd5743d0e3ba5621646b742432c5"
      ("%b" % u).length.should == 160
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
      xkk = SRP.sha1_hex(xss)
      xkk.should == "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      mm = SRP.calc_M(@username, @salt, xaa, xbb, xkk, @N, @g)
      ("%x" % mm).should == "2da30b225850c17720ed483ae6d04bcb67e4448e"
    end

    it "should calculate H(AMK)" do
      xaa = "b1c4827b0ce416953789db123051ed990023f43b396236b86e12a2c69638fb8e"
      xmm = "d597503056af882d5b27b419302ac7b2ea9d7468"
      xkk = "5844898ea6e5f5d9b737bc0ba2fb9d5edd3f8e67"
      h_amk = SRP.calc_H_AMK(xaa, xmm, xkk, @N, @g)
      ("%x" % h_amk).should == "ffc955a9227f1bf1d87d66bebecba081f54dbb7a"
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
      k.should == "7556aa045aef2cdd07abaf0f665c3e818913186f".to_i(16)
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
      v.should == "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
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
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      srp = SRP::Verifier.new(1024)
      srp.set_b @b.to_i(16)
      bb = srp.generate_B(v)
      bb.should == "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
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
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      # v is from db
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      _proof = {:A => aa, :B => bb, :b => @b, 
        :I => @username, :s => @salt, :v => v}
      srp = SRP::Verifier.new(1024)
      srp.verify_session(_proof, "match insignificant")
      ss = srp.S
      ss.should == "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      kk = srp.K
      kk.should == "404bf923682abeeb3c8c9164d2cdb6b6ba21b64d"
    end

    it "should calculate verifier M and server proof" do
      # A is received in phase 1
      aa = "165366e23a10006a62fb8a0793757a299e2985103ad2e8cdee0cc37cac109f3f338ee12e2440eda97bfa7c75697709a5dc66faadca7806d43ea5839757d134ae7b28dd3333049198cc8d328998b8cd8352ff4e64b3bd5f08e40148d69b0843bce18cbbb30c7e4760296da5c92717fcac8bddc7875f55302e55d90a34226868d2"
      # B and b are saved from phase 1
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      # v is from db
      v = "321307d87ca3462f5b0cb5df295bea04498563794e5401899b2f32dd5cab5b7de9da78e7d62ea235e6d7f43a4ea09fea7c0dafdee6e79a1d12e2e374048deeaf5ba7c68e2ad952a3f5dc084400a7f1599a31d6d9d50269a9208db88f84090e8aa3c7b019f39529dcc19baa985a8d7ffb2d7628071d2313c9eaabc504d3333688"
      # S is validated
      ss = "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      # K = H(S)
      kk = SRP.sha1_hex(ss)
      client_M = "52fb39fcacc2d909675ea3cf2b967980fc40ae0"
      _proof = {:A => aa, :B => bb, :b => @b, 
        :I => @username, :s => @salt, :v => v}
      srp = SRP::Verifier.new(1024)
      srp.verify_session(_proof, client_M)
      srp.M.should == client_M
      srp.H_AMK.should == "d3668cebb1cba4b3d4a4cd8edde9d89279b9d1e9"
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
      bb = "56777d24af1121bd6af6aeb84238ff8d250122fe75ed251db0f47c289642ae7adb9ef319ce3ab23b6ecc97e5904749fc42f12bb016ecf39691db541f066667b8399bfa685c82b03ad8f92f75975ed086dbe0d470d4dd907ce11b19ee41b74aee72bd8445cde6b58c01f678e39ed9cd6b93c79382637df90777a96c10a768c510"
      mm = srp.process_challenge(@username, @password, @salt, bb)
      ss = srp.S
      ss.should == "7f44592cc616e0d761b2d3309d513b69b386c35f3ed9b11e6d43f15799b673d6dcfa4117b4456af978458d62ad61e1a37be625f46d2a5bd9a50aae359e4541275f0f4bd4b4caed9d2da224b491231f905d47abd9953179aa608854b84a0e0c6195e73715932b41ab8d0d4a2977e7642163be6802c5907fb9e233b8c96e457314"
      kk = srp.K
      kk.should == "404bf923682abeeb3c8c9164d2cdb6b6ba21b64d"
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
