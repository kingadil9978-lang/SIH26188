'use server'

import { createClient } from '@supabase/supabase-js'
import { revalidatePath } from 'next/cache'

// Replace with your actual Supabase details if you have them, 
// or keep these placeholders for testing:
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || 'https://your-project.supabase.co'
const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || 'your-anon-key'
const supabase = createClient(supabaseUrl, supabaseKey)

export async function createPost(formData) {
  const title = formData.get('title')
  const content = formData.get('content')

  if (supabaseUrl !== 'https://your-project.supabase.co') {
    await supabase.from('posts').insert([{ title, content }])
  } else {
    console.log('Submitted post:', { title, content })
  }

  revalidatePath('/')
}