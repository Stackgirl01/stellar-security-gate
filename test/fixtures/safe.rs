#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct SafeContract;

#[contractimpl]
impl SafeContract {
    pub fn withdraw(env: Env, from: Address, amount: i128) {
        from.require_auth();
        let balance: i128 = env.storage().instance().get(&from).unwrap_or(0);
        if balance >= amount {
            env.storage().instance().set(&from, &(balance - amount));
        }
    }

    pub fn get_balance(env: Env, who: Address) -> i128 {
        env.storage().instance().get(&who).unwrap_or(0)
    }
}
