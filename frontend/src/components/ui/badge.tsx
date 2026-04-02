import { cva, type VariantProps } from 'class-variance-authority'
import type * as React from 'react'

import { cn } from '../../lib/utils'

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold transition-colors focus:outline-none',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-blue-500 text-white',
        secondary: 'border-transparent bg-slate-700 text-slate-100',
        destructive: 'border-transparent bg-red-600 text-white',
        outline: 'text-slate-200 border-slate-600',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
)

function Badge({ className, variant, ...props }: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}

export { Badge, badgeVariants }
