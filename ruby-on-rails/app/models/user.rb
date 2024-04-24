# models/user.rb
class User < ApplicationRecord
    has_one_attached :image
  end