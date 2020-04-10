require 'sinatra'
require "sinatra/reloader" if development?

require 'json'
require 'jwt'
require 'json/jwt'
require 'net/https'
require 'httparty'

get '/' do
  erb :go_on
end

get '/authenticate' do
  string = params[:id_token]
  if string
    payload, header = JWT.decode(string , nil, false)
    jwks_url = "https://#{payload['iss']}/.well-known/jwks.json"
    jwks = JSON.parse(HTTParty.get(jwks_url).body)

    jwk = jwks["keys"].first
    key = JSON::JWK.new(jwk).to_key
    decoded_token = JWT.decode string, key, true, { algorithm: header['alg'] }

    user_id = [payload['iss'], payload['sub']].join('|')

    erb :index, locals: {
      payload: payload,
      header: header,
      jwks_url: jwks_url,
      jwks: jwks,
      decoded_token: decoded_token,
      user_id: user_id
    }
  else
    erb :go_on
  end
end
