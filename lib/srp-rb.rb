# -*- encoding: utf-8 -*-
=begin
This is a pure Ruby implementation of the Secure Remote
Password protocol (SRP-6a). SRP is a cryptographically
strong authentication protocol for password-based, mutual
authentication over an insecure network connection.

References
 * http://srp.stanford.edu/
 * http://srp.stanford.edu/demo/demo.html

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
require "openssl"
require "srp-rb/version"

module SRP
  class << self

    def sha1_hex(h)
      OpenSSL::Digest::SHA1.hexdigest([h].pack('H*'))
    end

    def sha1_str(s)
      OpenSSL::Digest::SHA1.hexdigest(s)
    end

    def bigrand(bytes)
      OpenSSL::Random.random_bytes(bytes).unpack("H*")[0]
    end

    # a^n (mod m)
    def modpow(a, n, m)
      r = 1
      while true
        r = r * a % m if n[0] == 1
        n >>= 1
        return r if n == 0
        a = a * a % m
      end
    end

    # SHA1 hashing function with padding.
    # Input is prefixed with 0 to meet N hex width.
    def H(n, *a)
      nlen = 2 * ((('%x' % [n]).length * 4 + 7) >> 3)
      hashin = a.map {|s|
        next unless s
        shex = s.class == String ? s : "%x" % s
        if shex.length > nlen
            raise "Bit width does not match - client uses different prime"
        end
        "0" * (nlen - shex.length) + shex
      }.join('')
      sha1_hex(hashin).hex % n
    end

    # Multiplier parameter
    # k = H(N, g)   (in SRP-6a)
    def calc_k(n, g)
      H(n, n, g)
    end

    # Private key (derived from username, raw password and salt)
    # x = H(salt || H(username || ':' || password))
    def calc_x(username, password, salt)
      spad = if salt.length.odd? then '0' else '' end
      sha1_hex(spad + salt + sha1_str([username, password].join(':'))).hex
    end

    # Random scrambling parameter
    # u = H(A, B)
    def calc_u(xaa, xbb, n)
      H(n, xaa, xbb)
    end

    # Password verifier
    # v = g^x (mod N)
    def calc_v(x, n, g)
      modpow(g, x, n)
    end

    # A = g^a (mod N)
    def calc_A(a, n, g)
      modpow(g, a, n)
    end

    # B = g^b + k v (mod N)
    def calc_B(b, k, v, n, g)
      (modpow(g, b, n) + k * v) % n
    end

    # Client secret
    # S = (B - (k * g^x)) ^ (a + (u * x)) % N
    def calc_client_S(bb, a, k, x, u, n, g)
      modpow((bb - k * modpow(g, x, n)) % n, (a+ x * u), n)
    end

    # Server secret
    # S = (A * v^u) ^ b % N
    def calc_server_S(aa, b, v, u, n)
      modpow((modpow(v, u, n) * aa), b, n)
    end

    # M = H(H(N) xor H(g), H(I), s, A, B, K)
    def calc_M(username, xsalt, xaa, xbb, xkk, n, g)
      hn = sha1_hex("%x" % n).hex
      hg = sha1_hex("%x" % g).hex
      hxor = "%x" % (hn ^ hg)
      hi = sha1_str(username)
      return H(n, hxor, hi, xsalt, xaa, xbb, xkk)
    end

    # H(A, M, K)
    def calc_H_AMK(xaa, xmm, xkk, n, g)
      H(n, xaa, xmm, xkk)
    end

    def Ng(group)
      case group
      when 1024
        @N = %w{
          EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C
          9C256576 D674DF74 96EA81D3 383B4813 D692C6E0 E0D5D8E2 50B98BE4
          8E495C1D 6089DAD1 5DC7D7B4 6154D6B6 CE8EF4AD 69B15D49 82559B29
          7BCF1885 C529F566 660E57EC 68EDBC3C 05726CC0 2FD4CBF4 976EAA9A
          FD5138FE 8376435B 9FC61D2F C0EB06E3
        }.join.hex
        @g = 2

      when 1536
        @N = %w{
          9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961
          4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843
          80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B
          E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5
          6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A
          F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E
          8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB
        }.join.hex
        @g = 2

      when 2048
        @N = %w{
          AC6BDB41 324A9A9B F166DE5E 1389582F AF72B665 1987EE07 FC319294
          3DB56050 A37329CB B4A099ED 8193E075 7767A13D D52312AB 4B03310D
          CD7F48A9 DA04FD50 E8083969 EDB767B0 CF609517 9A163AB3 661A05FB
          D5FAAAE8 2918A996 2F0B93B8 55F97993 EC975EEA A80D740A DBF4FF74
          7359D041 D5C33EA7 1D281E44 6B14773B CA97B43A 23FB8016 76BD207A
          436C6481 F1D2B907 8717461A 5B9D32E6 88F87748 544523B5 24B0D57D
          5EA77A27 75D2ECFA 032CFBDB F52FB378 61602790 04E57AE6 AF874E73
          03CE5329 9CCC041C 7BC308D8 2A5698F3 A8D0C382 71AE35F8 E9DBFBB6
          94B5C803 D89F7AE4 35DE236D 525F5475 9B65E372 FCD68EF2 0FA7111F
          9E4AFF73
        }.join.hex
        @g = 2

      when 3072
        @N = %w{
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF
        }.join.hex
        @g = 5

      when 4096
        @N = %w{
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
          FFFFFFFF FFFFFFFF
        }.join.hex
        @g = 5

      when 6144
        @N = %w{
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
          36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
          AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
          DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
          2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
          F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
          BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
          CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
          B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
          387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
          6DCC4024 FFFFFFFF FFFFFFFF
        }.join.hex
        @g = 5

      when 8192
        @N = %w{
          FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 29024E08
          8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD EF9519B3 CD3A431B
          302B0A6D F25F1437 4FE1356D 6D51C245 E485B576 625E7EC6 F44C42E9
          A637ED6B 0BFF5CB6 F406B7ED EE386BFB 5A899FA5 AE9F2411 7C4B1FE6
          49286651 ECE45B3D C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8
          FD24CF5F 83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
          670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B E39E772C
          180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 DE2BCBF6 95581718
          3995497C EA956AE5 15D22618 98FA0510 15728E5A 8AAAC42D AD33170D
          04507A33 A85521AB DF1CBA64 ECFB8504 58DBEF0A 8AEA7157 5D060C7D
          B3970F85 A6E1E4C7 ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226
          1AD2EE6B F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
          BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31 43DB5BFC
          E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7 88719A10 BDBA5B26
          99C32718 6AF4E23C 1A946834 B6150BDA 2583E9CA 2AD44CE8 DBBBC2DB
          04DE8EF9 2E8EFC14 1FBECAA6 287C5947 4E6BC05D 99B2964F A090C3A2
          233BA186 515BE7ED 1F612970 CEE2D7AF B81BDD76 2170481C D0069127
          D5B05AA9 93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34028492
          36C3FAB4 D27C7026 C1D4DCB2 602646DE C9751E76 3DBA37BD F8FF9406
          AD9E530E E5DB382F 413001AE B06A53ED 9027D831 179727B0 865A8918
          DA3EDBEB CF9B14ED 44CE6CBA CED4BB1B DB7F1447 E6CC254B 33205151
          2BD7AF42 6FB8F401 378CD2BF 5983CA01 C64B92EC F032EA15 D1721D03
          F482D7CE 6E74FEF6 D55E702F 46980C82 B5A84031 900B1C9E 59E7C97F
          BEC7E8F3 23A97A7E 36CC88BE 0F1D45B7 FF585AC5 4BD407B2 2B4154AA
          CC8F6D7E BF48E1D8 14CC5ED2 0F8037E0 A79715EE F29BE328 06A1D58B
          B7C5DA76 F550AA3D 8A1FBFF0 EB19CCB1 A313D55C DA56C9EC 2EF29632
          387FE8D7 6E3C0468 043E8F66 3F4860EE 12BF2D5B 0B7474D6 E694F91E
          6DBE1159 74A3926F 12FEE5E4 38777CB6 A932DF8C D8BEC4D0 73B931BA
          3BC832B6 8D9DD300 741FA7BF 8AFC47ED 2576F693 6BA42466 3AAB639C
          5AE4F568 3423B474 2BF1C978 238F16CB E39D652D E3FDB8BE FC848AD9
          22222E04 A4037C07 13EB57A8 1A23F0C7 3473FC64 6CEA306B 4BCBC886
          2F8385DD FA9D4B7F A2C087E8 79683303 ED5BDD3A 062B3CF5 B3A278A6
          6D2A13F8 3F44F82D DF310EE0 74AB6A36 4597E899 A0255DC1 64F31CC5
          0846851D F9AB4819 5DED7EA1 B1D510BD 7EE74D73 FAF36BC3 1ECFA268
          359046F4 EB879F92 4009438B 481C6CD7 889A002E D5EE382B C9190DA6
          FC026E47 9558E447 5677E9AA 9E3050E2 765694DF C81F56E8 80B96E71
          60C980DD 98EDD3DF FFFFFFFF FFFFFFFF
        }.join.hex
        @g = 19

      else
        raise NotImplementedError
      end
      return [@N, @g]
    end
  end


  class Verifier
    attr_reader :N, :g, :k, :A, :B, :b, :S, :K, :M, :H_AMK

    def initialize group=1024
      # select modulus (N) and generator (g)
      @N, @g = SRP.Ng group
      @k = SRP.calc_k(@N, @g)
    end

    # Initial user creation for the persistance layer.
    # Not part of the authentication process.
    # Returns { <username>, <password verifier>, <salt> }
    def generate_userauth username, password
      @salt ||= random_salt
      x = SRP.calc_x(username, password, @salt)
      v = SRP.calc_v(x, @N, @g)
      return {:username => username, :verifier => "%x" % v, :salt => @salt}
    end

    # Authentication phase 1 - create challenge.
    # Returns Hash with challenge for client and proof to be stored on server.
    # Parameters should be given in hex.
    def get_challenge_and_proof username, xverifier, xsalt, xaa
      # SRP-6a safety check
      return false if (xaa.to_i(16) % @N) == 0
      generate_B(xverifier)
      return {
        :challenge    => {:B => @B, :salt => xsalt},
        :proof        => {:A => xaa, :B => @B, :b => "%x" % @b,
                          :I => username, :s => xsalt, :v => xverifier}
      }
    end

    # returns H_AMK on success, None on failure
    # User -> Host:  M = H(H(N) xor H(g), H(I), s, A, B, K)
    # Host -> User:  H(A, M, K)
    def verify_session proof, client_M
      @A = proof[:A]
      @B = proof[:B]
      @b = proof[:b].to_i(16)
      username = proof[:I]
      xsalt = proof[:s]
      v = proof[:v].to_i(16)

      u = SRP.calc_u(@A, @B, @N)
      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = "%x" % SRP.calc_server_S(@A.to_i(16), @b, v, u, @N)
      @K = SRP.sha1_hex(@S)

      # calculate match
      @M = "%x" % SRP.calc_M(username, xsalt, @A, @B, @K, @N, @g)

      if @M == client_M
        # authentication succeeded
        @H_AMK = "%x" % SRP.calc_H_AMK(@A, @M, @K, @N, @g)
        return @H_AMK
      end
      return false
    end

    def random_salt
      "%x" % SRP.bigrand(10).hex
    end

    def random_bignum
      SRP.bigrand(32).hex
    end

    # generates challenge
    # input verifier in hex
    def generate_B xverifier
      v = xverifier.to_i(16)
      @b ||= random_bignum
      @B = "%x" % SRP.calc_B(@b, k, v, @N, @g)
    end
  end # Verifier


  class Client
    attr_reader :N, :g, :k, :a, :A, :S, :K, :M, :H_AMK

    def initialize group=1024
      # select modulus (N) and generator (g)
      @N, @g = SRP.Ng group
      @k = SRP.calc_k(@N, @g)
    end

    def start_authentication
      generate_A
    end

    # Process initiated authentication challenge.
    # Returns M if authentication is successful, false otherwise.
    # Salt and B should be given in hex.
    def process_challenge username, password, xsalt, xbb
      bb = xbb.to_i(16)
      # SRP-6a safety check
      return false if (bb % @N) == 0

      x = SRP.calc_x(username, password, xsalt)
      u = SRP.calc_u(@A, xbb, @N)

      # SRP-6a safety check
      return false if u == 0

      # calculate session key
      @S = "%x" % SRP.calc_client_S(bb, @a, @k, x, u, @N, @g)
      @K = SRP.sha1_hex(@S)

      # calculate match
      @M = "%x" % SRP.calc_M(username, xsalt, @A, xbb, @K, @N, @g)

      # calculate verifier
      @H_AMK = "%x" % SRP.calc_H_AMK(@A, @M, @K, @N, @g)

      return @M
    end

    def verify server_HAMK
      return false unless @H_AMK
      @H_AMK == server_HAMK
    end

    def random_bignum
      SRP.bigrand(32).hex
    end

    def generate_A
      @a ||= random_bignum
      @A = "%x" % SRP.calc_A(@a, @N, @g)
    end
  end # Client
end
