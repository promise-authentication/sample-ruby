require 'sinatra'
require "sinatra/reloader" if development?

require 'json'
require 'jwt'
require 'json/jwt'
require 'net/https'
require 'httparty'

get '/authenticate' do
  string = params[:id_token]
  payload, header = JWT.decode(string , nil, false)
  jwks_url = "https://#{payload['iss']}/.well-known/jwks.json"
  jwks = JSON.parse(HTTParty.get(jwks_url).body)

  jwk = jwks["keys"].first
  key = JSON::JWK.new(jwk).to_key
  decoded_token = JWT.decode string, key, true, { algorithm: header['alg'] }

  erb :index, locals: {
    payload: payload,
    header: header,
    jwks_url: jwks_url,
    jwks: jwks,
    decoded_token: decoded_token
  }
end
