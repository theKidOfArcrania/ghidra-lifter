{-# LANGUAGE DeriveGeneric #-}
module Data.Ghidra.PcodeTypes (PcodeOpType(..)) where

import GHC.Generics     (Generic)
import Data.Aeson       (FromJSON, ToJSON)

data PcodeOpType =
    UNIMPLEMENTED    -- Place holder for unimplemented instruction
  | COPY             -- Copy one operand to another
  | LOAD             -- Dereference a pointer into specified space
  | STORE            -- Store at a pointer into specified space
  | BRANCH           -- Always branch
  | CBRANCH          -- Conditional branch
  | BRANCHIND        -- An indirect branch (jumptable)

  | CALL             -- A call with absolute address
  | CALLIND          -- An indirect call
  | CALLOTHER        -- Other unusual subroutine calling conventions
  | RETURN           -- A return from subroutine

  | INT_EQUAL        -- Return TRUE if operand1 == operand2
  | INT_NOTEQUAL     -- Return TRUE if operand1 != operand2
  | INT_SLESS        -- Return TRUE if signed op1 < signed op2
  | INT_SLESSEQUAL   -- Return TRUE if signed op1 <= signed op2
  | INT_LESS         -- Return TRUE if unsigned op1 < unsigned op2
  | INT_LESSEQUAL    -- Return TRUE if unsigned op1 <= unsigned op2
  | INT_ZEXT         -- Zero extend operand
  | INT_SEXT         -- Sign extend operand
  | INT_ADD          -- Unsigned addition of operands of same size
  | INT_SUB          -- Unsigned subtraction of operands of same size
  | INT_CARRY        -- TRUE if adding two operands has overflow (carry)
  | INT_SCARRY       -- TRUE if carry in signed addition of 2 ops
  | INT_SBORROW      -- TRUE if borrow in signed subtraction of 2 ops
  | INT_2COMP        -- Twos complement (for subtracting) of operand
  | INT_NEGATE
  | INT_XOR          -- Exclusive OR of two operands of same size
  | INT_AND
  | INT_OR
  | INT_LEFT         -- Left shift
  | INT_RIGHT        -- Right shift zero fill
  | INT_SRIGHT       -- Signed right shift
  | INT_MULT         -- Integer multiplication
  | INT_DIV          -- Unsigned integer division
  | INT_SDIV         -- Signed integer division
  | INT_REM          -- Unsigned mod (remainder)
  | INT_SREM         -- Signed mod (remainder)

  | BOOL_NEGATE      -- Boolean negate or not
  | BOOL_XOR         -- Boolean xor
  | BOOL_AND         -- Boolean and (&&)
  | BOOL_OR          -- Boolean or (||)

  | FLOAT_EQUAL      -- Return TRUE if operand1 == operand2
  | FLOAT_NOTEQUAL   -- Return TRUE if operand1 != operand2
  | FLOAT_LESS       -- Return TRUE if op1 < op2
  | FLOAT_LESSEQUAL  -- Return TRUE if op1 <= op2
  | UNUSED_1
  | FLOAT_NAN        -- Return TRUE if neither op1 is NaN
  | FLOAT_ADD        -- float addition
  | FLOAT_DIV        -- float division
  | FLOAT_MULT       -- float multiplication
  | FLOAT_SUB        -- float subtraction
  | FLOAT_NEG        -- float negation
  | FLOAT_ABS        -- float absolute value
  | FLOAT_SQRT       -- float square root

  | INT2FLOAT        -- convert int type to float type
  | FLOAT2FLOAT      -- convert between float sizes
  | TRUNC            -- round towards zero
  | CEIL             -- round towards +infinity
  | FLOOR            -- round towards -infinity
  | ROUND            -- round towards nearest

  | MULTIEQUAL       -- Output equal to one of inputs, depending on execution
  | INDIRECT         -- Output probably equals input, but may be indirectly affected
  | PIECE            -- Output is constructed from multiple peices
  | SUBPIECE         -- Output is a subpiece of input0, input1=offset into input0

  | CAST             -- Cast from one type to another
  | PTRADD           -- outptr = ptrbase,offset, (size multiplier)
  | PTRSUB           -- outptr = &(ptr->subfield)
  | SEGMENTOP
  | CPOOLREF
  | NEW
  | INSERT
  | EXTRACT
  | POPCOUNT
  | INVALID_OP
  deriving (Eq, Show, Read, Generic, Enum)

instance FromJSON PcodeOpType
instance ToJSON PcodeOpType
