use anchor_lang::prelude::*;
use switchboard_v2::{VrfAccountData, VrfRequestRandomness,SbState, OracleQueueAccountData, 
    SWITCHBOARD_PROGRAM_ID, PermissionAccountData};
use anchor_lang::solana_program::native_token::LAMPORTS_PER_SOL;
use anchor_spl::token::{self, TokenAccount, Token, Mint, MintTo};
use x25519_dalek::{PublicKey,EphemeralSecret,SharedSecret,};
const VRF_REQUEST_COST: u64 = 2 * LAMPORTS_PER_SOL / 1000;
const MULTIPLIER: u64 = 100000000;
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod spam_tokens {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>, bump: u8) -> Result<()>{
        let spam_client = &mut ctx.accounts.spam_client;
        spam_client.authority = ctx.accounts.authority.key();
        spam_client.result = 0;
        spam_client.vrf = ctx.accounts.vrf.key();
        spam_client.mint = ctx.accounts.mint.key();
        spam_client.bump = bump;
        Ok(())
    }


    pub fn request_randomness(ctx: Context<RequestRandomness>, vrf_permission_bump: u8, switchboard_state_bump: u8) -> Result<()> {
        
        let combined_balance = ctx
            .accounts
            .payer_wallet
            .amount
            .checked_add(ctx.accounts.escrow.amount)
            .unwrap_or(0);
        if combined_balance < VRF_REQUEST_COST {
            msg!(
                "missing funds to request randomness, need {}, have {}",
                VRF_REQUEST_COST,
                combined_balance
            );
            return Err(error!(SpamError::InsufficientFunds));
        }
        else {
            let request_randomness_ctx = VrfRequestRandomness{
                authority: ctx.accounts.authority.to_account_info(),
                vrf: ctx.accounts.vrf.to_account_info(),
                oracle_queue: ctx.accounts.oracle_queue.to_account_info(),
                queue_authority: ctx.accounts.queue_authority.to_account_info(),
                data_buffer: ctx.accounts.data_buffer.clone(),
                permission: ctx.accounts.permission.to_account_info(),
                escrow: ctx.accounts.escrow.clone(),
                payer_wallet: ctx.accounts.payer_wallet.clone(),
                payer_authority: ctx.accounts.payer_authority.to_account_info(),
                recent_blockhashes: ctx.accounts.recent_blockhashes.clone(),
                program_state: ctx.accounts.program_state.to_account_info(),
                token_program: ctx.accounts.token_program.to_account_info(),
        };
            request_randomness_ctx.invoke_signed(
            ctx.accounts.switchboard_program.clone(),
            switchboard_state_bump,
            vrf_permission_bump,
            &[&[
                b"spam_tokens",
                ctx.accounts.vrf.key().as_ref(),
                ctx.accounts.authority.key().as_ref(),
                &[ctx.accounts.spam_client.bump.clone()],
            ]]

        )?;
    }
     msg!("randomness requested successfully..");
        Ok(())
    }
    pub fn mint_spam_tokens(ctx: Context<MintSpamTokens>, bump: u8) -> Result<()> {
        let vrf = ctx.accounts.vrf.load()?;
        let vrf_buffer = vrf.get_result()?;
        let vrf_result: &[u64] = bytemuck::cast_slice(&vrf_buffer[..]);
        let spam_tokens = MULTIPLIER.checked_mul(vrf_result[0]).unwrap();
        let signer_seeds:&[&[&[u8]]] = &[&[b"spam_tokens", &[ctx.accounts.spam_client.bump.clone()]]];
        let mint_to_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info().clone(),
            MintTo{
                mint: ctx.accounts.mint.to_account_info().clone(),
                authority: ctx.accounts.authority.to_account_info().clone(),
                to: ctx.accounts.recipient.to_account_info().clone(),
            },
            signer_seeds,
        );
        token::mint_to(mint_to_ctx, spam_tokens)?;
        let  spam_client = &mut ctx.accounts.spam_client;
        spam_client.mint = ctx.accounts.mint.key();
        spam_client.result = vrf_result[0];
        spam_client.bump = bump;
        spam_client.vrf = *ctx.accounts.vrf.to_account_info().key;
        spam_client.recipient = ctx.accounts.recipient.key();
        spam_client.authority = ctx.accounts.authority.key();
        spam_client.switchboard_queue = *ctx.accounts.oracle_queue.to_account_info().key;



        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init, 
        seeds = [b"spam_tokens".as_ref(), vrf.key().as_ref(),authority.key().as_ref()],
        bump,
        payer = payer,
        space = 8 + std::mem::size_of::<SpamClient>(),
    )]
    pub spam_client: Account<'info, SpamClient>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
    #[account(constraint = *vrf.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub vrf: AccountLoader<'info, VrfAccountData>,
    #[account(address = anchor_lang::solana_program::system_program::ID)]
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RequestRandomness<'info> {

    #[account(
        mut,
        seeds = [b"spam_tokens".as_ref(), vrf.key().as_ref(),authority.key().as_ref()],
        bump,
        has_one = authority @ SpamError::InvalidAuthority,
        has_one = vrf @ SpamError::InvalidVrf,
    )]
    pub spam_client: Account<'info, SpamClient>,
    pub authority: Signer<'info>,
    #[account(mut,
        has_one = escrow,
        constraint = *vrf.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub vrf: AccountLoader<'info, VrfAccountData>,
    #[account(mut, constraint = 
        oracle_queue.load()?.authority == queue_authority.key() 
        && *oracle_queue.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub oracle_queue: AccountLoader<'info, OracleQueueAccountData>,
    pub queue_authority: UncheckedAccount<'info>,
    #[account(mut, constraint = *data_buffer.owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub data_buffer: AccountInfo<'info>,
    #[account(mut, constraint = *permission.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub permission: AccountLoader<'info, PermissionAccountData>,
    #[account(
        mut,
        constraint = escrow.owner == program_state.key() 
        && escrow.mint == program_state.load()?.token_mint)]
    pub escrow: Account<'info, TokenAccount>,
    #[account(mut, constraint = *program_state.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub program_state: AccountLoader<'info, SbState>,
    #[account(executable, constraint = switchboard_program.key() == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub switchboard_program: AccountInfo<'info>,
    #[account(address = anchor_lang::solana_program::sysvar::recent_blockhashes::ID)]
    pub recent_blockhashes: AccountInfo<'info>,
    #[account(address = anchor_lang::solana_program::sysvar::rent::ID)]
    #[account(mut, constraint = payer_wallet.owner == payer_authority.key()
                    && payer_wallet.mint == escrow.mint)]
    pub payer_wallet: Account<'info, TokenAccount>,
    pub payer_authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct MintSpamTokens<'info>{

    #[account(
        constraint = *vrf.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardQueue,
    )]
    pub vrf:  AccountLoader<'info, VrfAccountData>,
    #[account(constraint = *oracle_queue.to_account_info().owner == SWITCHBOARD_PROGRAM_ID @ SpamError::InvalidSwitchboardAccount)]
    pub oracle_queue: AccountLoader<'info, OracleQueueAccountData>,
    #[account(
        mut,
        seeds = [b"spam_tokens".as_ref(), vrf.key().as_ref(),authority.key().as_ref()],
        bump,
        has_one = vrf,
        has_one = mint,
    )]
    pub spam_client: Account<'info, SpamClient>,

    #[account(mut)]
    pub recipient: Account<'info, TokenAccount>,

    pub mint: Account<'info, Mint>,
    pub authority: Signer<'info>,
    pub token_program: Program<'info, Token>,
}


#[account]
pub struct SpamClient{
    pub mint: Pubkey,
    pub result: u64,
    pub bump: u8,
    pub vrf: Pubkey,
    pub recipient: Pubkey,
    pub switchboard_queue: Pubkey,
    pub authority: Pubkey,
}

#[error_code]
pub enum SpamError{
    InvalidSwitchboardAccount,
    InvalidSwitchboardQueue,
    InvalidAuthority,
    InvalidCalculation,
    InvalidVrf,
    InsufficientFunds,
}